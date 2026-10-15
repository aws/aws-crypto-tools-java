// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.materialproviders.KeyringTests.MPL;
import static software.amazon.cryptography.materialproviders.KeyringTests.allSuites;
import static software.amazon.cryptography.materialproviders.KeyringTests.decryptionMaterials;
import static software.amazon.cryptography.materialproviders.KeyringTests.encryptionMaterials;
import static software.amazon.cryptography.materialproviders.KeyringTests.expectedDecryption;
import static software.amazon.cryptography.materialproviders.KeyringTests.map;
import static software.amazon.cryptography.materialproviders.KmsKeyringTests.REGION;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.cryptography.materialproviders.KeyringTests.Outcomes;
import software.amazon.cryptography.materialproviders.KeyringTests.Pair;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.internal.NativeKeyring;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsRsaKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRawEcdhKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRawRsaKeyringInput;
import software.amazon.cryptography.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.model.EphemeralPrivateKeyToStaticPublicKeyInput;
import software.amazon.cryptography.materialproviders.model.PublicKeyDiscoveryInput;
import software.amazon.cryptography.materialproviders.model.RawPrivateKeyToStaticPublicKeyInput;
import software.amazon.cryptography.mpl.keyrings.AwsKmsRsaKeyring;
import software.amazon.cryptography.mpl.keyrings.EcdhCurveSpec;
import software.amazon.cryptography.mpl.keyrings.PaddingScheme;
import software.amazon.cryptography.mpl.keyrings.RawEcdhKeyring;
import software.amazon.cryptography.mpl.keyrings.RawEcdhStaticConfigurations;
import software.amazon.cryptography.mpl.keyrings.RawRsaKeyring;
import software.amazon.cryptography.primitives.model.ECDHCurveSpec;

// The keyring builders that take JCA keys, against the reference keyring built from the keys' PEM/DER bytes:
// each side decrypts what the other encrypted, and the failures of a key of the wrong kind compare exactly.
class JcaKeyOverloadsTest {

  private static final String NAMESPACE = "namespace";
  private static final String NAME = "name";

  private final Object reference = ReferenceMpl.materialProviders();
  private final Outcomes outcomes = new Outcomes();
  private final FakeAws aws = FakeAws.start();

  @AfterEach
  void close() {
    aws.close();
  }

  @Test
  void rawRsaFromJcaKeys() throws GeneralSecurityException {
    KeyPair rsa = keyPair("RSA", null);
    for (PaddingScheme padding : PaddingScheme.values()) {
      Pair keyring = new Pair(
        new NativeKeyring(rsaBuilder(padding).publicKey(rsa.getPublic()).privateKey(rsa.getPrivate()).build()),
        ReferenceMpl.call(reference, "CreateRawRsaKeyring", rsaInput(padding, pem("PUBLIC KEY", rsa.getPublic().getEncoded()), pem("PRIVATE KEY", rsa.getPrivate().getEncoded())))
      );
      for (AlgorithmSuiteId suite : allSuites()) {
        String context = padding + " " + ReferenceMpl.describe(suite);
        EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false);
        keyring.assertSameEncrypt(outcomes, start, context);
        crossDecrypt(keyring, keyring, start, context);
      }
    }
  }

  // An EC key where an RSA key belongs fails as its PEM fails in the reference.
  @Test
  void rawRsaFromKeysOfAnotherKind() throws GeneralSecurityException {
    KeyPair ec = keyPair("EC", "secp256r1");
    PaddingScheme padding = PaddingScheme.OAEP_SHA256_MGF1;
    Pair encrypting = new Pair(
      new NativeKeyring(rsaBuilder(padding).publicKey(ec.getPublic()).build()),
      ReferenceMpl.call(reference, "CreateRawRsaKeyring", rsaInput(padding, pem("PUBLIC KEY", ec.getPublic().getEncoded()), null))
    );
    Pair decrypting = new Pair(
      new NativeKeyring(rsaBuilder(padding).privateKey(ec.getPrivate()).build()),
      ReferenceMpl.call(reference, "CreateRawRsaKeyring", rsaInput(padding, null, pem("PRIVATE KEY", ec.getPrivate().getEncoded())))
    );
    KeyPair rsa = keyPair("RSA", null);
    RawRsaKeyring good = rsaBuilder(padding).publicKey(rsa.getPublic()).build();
    for (AlgorithmSuiteId suite : allSuites()) {
      EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false);
      assertTrue(encrypting.assertSameEncrypt(outcomes, start, "EC public key").startsWith("throws"));
      EncryptionMaterials encrypted = new NativeKeyring(good).OnEncrypt(software.amazon.cryptography.materialproviders.model.OnEncryptInput.builder().materials(start).build()).materials();
      assertTrue(decrypting.assertSameDecrypt(outcomes, decryptionMaterials(encrypted), encrypted.encryptedDataKeys(), "EC private key").startsWith("throws"));
    }
  }

  // Static, ephemeral, and discovery configurations from JCA keys, on each NIST curve.
  @Test
  void rawEcdhFromJcaKeys() throws GeneralSecurityException {
    for (EcdhCurveSpec curve : Arrays.asList(EcdhCurveSpec.ECC_NIST_P256, EcdhCurveSpec.ECC_NIST_P384, EcdhCurveSpec.ECC_NIST_P521)) {
      String jcaCurve = curve == EcdhCurveSpec.ECC_NIST_P256 ? "secp256r1" : curve == EcdhCurveSpec.ECC_NIST_P384 ? "secp384r1" : "secp521r1";
      KeyPair sender = keyPair("EC", jcaCurve);
      KeyPair recipient = keyPair("EC", jcaCurve);
      byte[] senderPem = pem("PRIVATE KEY", sender.getPrivate().getEncoded());
      byte[] recipientPem = pem("PRIVATE KEY", recipient.getPrivate().getEncoded());
      byte[] recipientDer = recipient.getPublic().getEncoded();

      Pair statically = ecdh(
        curve,
        RawEcdhStaticConfigurations.rawPrivateKeyToStaticPublicKey(sender.getPrivate(), recipient.getPublic()),
        software.amazon.cryptography.materialproviders.model.RawEcdhStaticConfigurations
          .builder()
          .RawPrivateKeyToStaticPublicKey(
            RawPrivateKeyToStaticPublicKeyInput.builder().senderStaticPrivateKey(ByteBuffer.wrap(senderPem)).recipientPublicKey(ByteBuffer.wrap(recipientDer)).build()
          )
          .build()
      );
      Pair ephemeral = ecdh(
        curve,
        RawEcdhStaticConfigurations.ephemeralPrivateKeyToStaticPublicKey(recipient.getPublic()),
        software.amazon.cryptography.materialproviders.model.RawEcdhStaticConfigurations
          .builder()
          .EphemeralPrivateKeyToStaticPublicKey(EphemeralPrivateKeyToStaticPublicKeyInput.builder().recipientPublicKey(ByteBuffer.wrap(recipientDer)).build())
          .build()
      );
      Pair discovery = ecdh(
        curve,
        RawEcdhStaticConfigurations.publicKeyDiscovery(recipient.getPrivate()),
        software.amazon.cryptography.materialproviders.model.RawEcdhStaticConfigurations
          .builder()
          .PublicKeyDiscovery(PublicKeyDiscoveryInput.builder().recipientStaticPrivateKey(ByteBuffer.wrap(recipientPem)).build())
          .build()
      );
      for (AlgorithmSuiteId suite : allSuites()) {
        String context = curve + " " + ReferenceMpl.describe(suite);
        EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false);
        // The provider info holds both public keys, so the static keyrings' encrypted data keys agree up to the ciphertext.
        assertEquals(
          statically.referenceEncrypt(start).encryptedDataKeys().get(0).keyProviderInfo(),
          statically.nativeEncrypt(start).encryptedDataKeys().get(0).keyProviderInfo(),
          context
        );
        crossDecrypt(statically, statically, start, context + " static");
        crossDecrypt(statically, discovery, start, context + " static to discovery");
        crossDecrypt(ephemeral, discovery, start, context + " ephemeral to discovery");
        assertTrue(discovery.assertSameEncrypt(outcomes, start, context + " discovery cannot encrypt").startsWith("throws"));
      }
    }
  }

  // The DER from KMS GetPublicKey, decoded with the JCA, encrypts as its PEM does; KMS decrypts either side's result.
  @Test
  void kmsRsaFromAJcaPublicKey() throws GeneralSecurityException {
    KmsClient kms = ReferenceAws.kms(aws, REGION);
    String arn = aws.kms().createRsaKey(REGION, "RSA_2048");
    byte[] pem = aws.kms().publicKeyPem(arn).getBytes(StandardCharsets.UTF_8);
    PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der(pem)));
    for (EncryptionAlgorithmSpec algorithm : Arrays.asList(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1, EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)) {
      Pair encrypting = new Pair(
        new NativeKeyring(AwsKmsRsaKeyring.builder().publicKey(publicKey).kmsKeyId(arn).encryptionAlgorithm(algorithm).build()),
        ReferenceMpl.call(reference, "CreateAwsKmsRsaKeyring", kmsRsaInput(ByteBuffer.wrap(pem), arn, algorithm, null))
      );
      Pair decrypting = new Pair(
        MPL.CreateAwsKmsRsaKeyring(kmsRsaInput(null, arn, algorithm, kms)),
        ReferenceMpl.call(reference, "CreateAwsKmsRsaKeyring", kmsRsaInput(null, arn, algorithm, kms))
      );
      for (AlgorithmSuiteId suite : allSuites()) {
        if (software.amazon.cryptography.materialproviders.internal.Convert.suite(suite).isSigning()) {
          continue;
        }
        String context = algorithm + " " + ReferenceMpl.describe(suite);
        EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false);
        encrypting.assertSameEncrypt(outcomes, start, context);
        crossDecrypt(encrypting, decrypting, start, context);
      }
    }
  }

  // Both sides decrypt what each side of {@code encrypting} encrypted, and get the data key back.
  private void crossDecrypt(Pair encrypting, Pair decrypting, EncryptionMaterials start, String context) {
    for (EncryptionMaterials encrypted : Arrays.asList(encrypting.nativeEncrypt(start), encrypting.referenceEncrypt(start))) {
      String decrypted = decrypting.assertSameDecrypt(outcomes, decryptionMaterials(encrypted), encrypted.encryptedDataKeys(), context);
      assertEquals(ReferenceMpl.describe(expectedDecryption(encrypted)), decrypted, context);
    }
  }

  private Pair ecdh(EcdhCurveSpec curve, RawEcdhStaticConfigurations nativeScheme, software.amazon.cryptography.materialproviders.model.RawEcdhStaticConfigurations referenceScheme) {
    CreateRawEcdhKeyringInput input = CreateRawEcdhKeyringInput.builder().curveSpec(ECDHCurveSpec.valueOf(curve.name())).KeyAgreementScheme(referenceScheme).build();
    return new Pair(
      new NativeKeyring(RawEcdhKeyring.builder().curveSpec(curve).keyAgreementScheme(nativeScheme).build()),
      ReferenceMpl.call(reference, "CreateRawEcdhKeyring", input)
    );
  }

  private static RawRsaKeyring.Builder rsaBuilder(PaddingScheme padding) {
    return RawRsaKeyring.builder().keyNamespace(NAMESPACE).keyName(NAME).paddingScheme(padding);
  }

  private static CreateRawRsaKeyringInput rsaInput(PaddingScheme padding, byte[] publicKey, byte[] privateKey) {
    return CreateRawRsaKeyringInput
      .builder()
      .keyNamespace(NAMESPACE)
      .keyName(NAME)
      .paddingScheme(software.amazon.cryptography.materialproviders.model.PaddingScheme.valueOf(padding.name()))
      .publicKey(publicKey == null ? null : ByteBuffer.wrap(publicKey))
      .privateKey(privateKey == null ? null : ByteBuffer.wrap(privateKey))
      .build();
  }

  private static CreateAwsKmsRsaKeyringInput kmsRsaInput(ByteBuffer publicKey, String arn, EncryptionAlgorithmSpec algorithm, KmsClient kms) {
    return CreateAwsKmsRsaKeyringInput.builder().publicKey(publicKey).kmsKeyId(arn).encryptionAlgorithm(algorithm).kmsClient(kms).grantTokens(Collections.<String>emptyList()).build();
  }

  private static KeyPair keyPair(String algorithm, String curve) throws GeneralSecurityException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
    if (curve == null) {
      generator.initialize(2048);
    } else {
      generator.initialize(new ECGenParameterSpec(curve));
    }
    return generator.generateKeyPair();
  }

  // Written independently of the library's PEM writer: 64-column Base64 lines, LF line ends.
  private static byte[] pem(String type, byte[] der) {
    String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
    return ("-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n").getBytes(StandardCharsets.US_ASCII);
  }

  private static byte[] der(byte[] pem) {
    String text = new String(pem, StandardCharsets.US_ASCII);
    List<String> lines = Arrays.asList(text.split("\n"));
    StringBuilder body = new StringBuilder();
    for (String line : lines) {
      if (!line.startsWith("-----")) {
        body.append(line.trim());
      }
    }
    return Base64.getDecoder().decode(body.toString());
  }
}
