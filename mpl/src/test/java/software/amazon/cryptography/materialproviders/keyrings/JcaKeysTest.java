// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keyrings;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;

// The JCA key overloads of the RSA and ECDH keyrings and configurations: the bytes they store, keys without an encoding, nulls,
// and the temporary encodings they clear. JcaKeyOverloadsTest compares their keyrings with the reference.
class JcaKeysTest {

  private static final String ARN = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";

  @Test
  void theKeyringsStoreThePemOfTheEncoding() throws Exception {
    KeyPair rsa = keyPair("RSA", null);
    byte[] rawRsa = rsa().publicKey(rsa.getPublic()).build().publicKey().get();
    byte[] kmsRsa = AwsKmsRsaKeyring.builder().publicKey(rsa.getPublic()).kmsKeyId(ARN).encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256).build().publicKey().get();
    for (byte[] pem : Arrays.asList(rawRsa, kmsRsa)) {
      String text = new String(pem, StandardCharsets.US_ASCII);
      assertTrue(text.startsWith("-----BEGIN PUBLIC KEY-----"), text);
      assertArrayEquals(rsa.getPublic().getEncoded(), der(text));
    }
    KeyPair ec = keyPair("EC", "secp256r1");
    String privatePem = new String(RawEcdhKeyAgreementScheme.publicKeyDiscovery(ec.getPrivate()).privateKey().toByteArray(), StandardCharsets.US_ASCII);
    assertTrue(privatePem.startsWith("-----BEGIN PRIVATE KEY-----"), privatePem);
    assertArrayEquals(ec.getPrivate().getEncoded(), der(privatePem));
    assertArrayEquals(ec.getPublic().getEncoded(), RawEcdhKeyAgreementScheme.ephemeralPrivateKeyToStaticPublicKey(ec.getPublic()).recipientPublicKey());
  }

  // The keyring reads only these fields, so equal fields mean it behaves as with the byte form.
  @Test
  void kmsEcdhConfigurationsFromJcaKeysMatchTheByteForm() {
    PublicKey sender = keyPair("EC", "secp384r1").getPublic();
    PublicKey recipient = keyPair("EC", "secp384r1").getPublic();
    KmsEcdhKeyAgreementScheme fetched = KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey(ARN, recipient);
    KmsEcdhKeyAgreementScheme fetchedBytes = KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey(ARN, recipient.getEncoded());
    KmsEcdhKeyAgreementScheme supplied = KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey(ARN, sender, recipient);
    KmsEcdhKeyAgreementScheme suppliedBytes = KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey(ARN, sender.getEncoded(), recipient.getEncoded());
    for (KmsEcdhKeyAgreementScheme[] pair : new KmsEcdhKeyAgreementScheme[][] { { fetched, fetchedBytes }, { supplied, suppliedBytes } }) {
      assertEquals(KmsEcdhKeyAgreementScheme.Kind.KMS_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY, pair[0].kind());
      assertEquals(pair[1].kmsIdentifier(), pair[0].kmsIdentifier());
      assertArrayEquals(pair[1].senderPublicKey(), pair[0].senderPublicKey());
      assertArrayEquals(pair[1].recipientPublicKey(), pair[0].recipientPublicKey());
    }
    assertArrayEquals(recipient.getEncoded(), fetched.recipientPublicKey());
    assertArrayEquals(sender.getEncoded(), supplied.senderPublicKey());
  }

  @Test
  void aKeyWithoutAnEncodingIsAValidationFailure() {
    PublicKey publicKey = new Unencoded();
    PrivateKey privateKey = new Unencoded();
    assertMessage("publicKey has no encoded form", () -> rsa().publicKey(publicKey));
    assertMessage("privateKey has no encoded form", () -> rsa().privateKey(privateKey));
    assertMessage("publicKey has no encoded form", () -> AwsKmsRsaKeyring.builder().publicKey(publicKey));
    assertMessage("recipientPublicKey has no encoded form", () -> RawEcdhKeyAgreementScheme.ephemeralPrivateKeyToStaticPublicKey(publicKey));
    assertMessage("recipientStaticPrivateKey has no encoded form", () -> RawEcdhKeyAgreementScheme.publicKeyDiscovery(privateKey));
    assertMessage("senderStaticPrivateKey has no encoded form", () -> RawEcdhKeyAgreementScheme.rawPrivateKeyToStaticPublicKey(privateKey, keyPair("EC", "secp256r1").getPublic()));
    assertMessage("recipientPublicKey has no encoded form", () -> RawEcdhKeyAgreementScheme.rawPrivateKeyToStaticPublicKey(keyPair("EC", "secp256r1").getPrivate(), publicKey));
    PublicKey ec = keyPair("EC", "secp256r1").getPublic();
    assertMessage("recipientPublicKey has no encoded form", () -> KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey(ARN, publicKey));
    assertMessage("senderPublicKey has no encoded form", () -> KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey(ARN, publicKey, ec));
    assertMessage("recipientPublicKey has no encoded form", () -> KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey(ARN, ec, publicKey));
  }

  @Test
  void nullKeys() throws Exception {
    assertMessage("A publicKey or a privateKey is required", () -> rsa().publicKey((PublicKey) null).privateKey((PrivateKey) null).build());
    assertMessage(
      "A publicKey or a kmsClient is required",
      () -> AwsKmsRsaKeyring.builder().publicKey((PublicKey) null).kmsKeyId(ARN).encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256).build()
    );
    KeyPair ec = keyPair("EC", "secp256r1");
    assertMessage("Missing value for required field `senderStaticPrivateKey`", () -> RawEcdhKeyAgreementScheme.rawPrivateKeyToStaticPublicKey((PrivateKey) null, ec.getPublic()));
    assertMessage("Missing value for required field `recipientPublicKey`", () -> RawEcdhKeyAgreementScheme.rawPrivateKeyToStaticPublicKey(ec.getPrivate(), (PublicKey) null));
    assertMessage("Missing value for required field `recipientPublicKey`", () -> RawEcdhKeyAgreementScheme.ephemeralPrivateKeyToStaticPublicKey((PublicKey) null));
    assertMessage("Missing value for required field `recipientStaticPrivateKey`", () -> RawEcdhKeyAgreementScheme.publicKeyDiscovery((PrivateKey) null));
    PublicKey key = ec.getPublic();
    assertMessage("Missing value for required field `senderKmsIdentifier`", () -> KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey(null, key));
    assertMessage("Missing value for required field `recipientPublicKey`", () -> KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey(ARN, (PublicKey) null));
    assertMessage("Missing value for required field `senderKmsIdentifier`", () -> KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey(null, key, key));
    assertMessage("Missing value for required field `senderPublicKey`", () -> KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey(ARN, null, key));
    assertMessage("Missing value for required field `recipientPublicKey`", () -> KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey(ARN, key, null));
  }

  @Test
  void configurationsFromJcaKeysHaveTheirKind() throws Exception {
    KeyPair ec = keyPair("EC", "secp256r1");
    assertEquals(RawEcdhKeyAgreementScheme.Kind.RAW_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY, RawEcdhKeyAgreementScheme.rawPrivateKeyToStaticPublicKey(ec.getPrivate(), ec.getPublic()).kind());
    assertEquals(RawEcdhKeyAgreementScheme.Kind.EPHEMERAL_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY, RawEcdhKeyAgreementScheme.ephemeralPrivateKeyToStaticPublicKey(ec.getPublic()).kind());
    assertEquals(RawEcdhKeyAgreementScheme.Kind.PUBLIC_KEY_DISCOVERY, RawEcdhKeyAgreementScheme.publicKeyDiscovery(ec.getPrivate()).kind());
  }

  // A private key's encoding is a secret: the builders clear the array getEncoded() returned once they hold the PEM.
  @Test
  void privateKeyEncodingsAreCleared() throws Exception {
    KeyPair rsa = keyPair("RSA", null);
    Recording recordingRsa = new Recording(rsa.getPrivate());
    RawRsaKeyring keyring = rsa().publicKey(rsa.getPublic()).privateKey(recordingRsa).build();
    assertCleared(recordingRsa);
    assertTrue(keyring.onDecrypt(OnDecryptRequest.builder().materials(software.amazon.cryptography.materialproviders.DecryptionMaterials.builder(software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).build()).encryptedDataKeys(keyring.onEncrypt(OnEncryptRequest.builder().materials(software.amazon.cryptography.materialproviders.EncryptionMaterials.builder(software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).build()).build()).materials().encryptedDataKeys()).build()).materials().plaintextDataKey().isPresent());

    KeyPair ec = keyPair("EC", "secp256r1");
    Recording sender = new Recording(ec.getPrivate());
    RawEcdhKeyAgreementScheme.rawPrivateKeyToStaticPublicKey(sender, ec.getPublic());
    assertCleared(sender);
    Recording recipient = new Recording(ec.getPrivate());
    RawEcdhKeyAgreementScheme.publicKeyDiscovery(recipient);
    assertCleared(recipient);
  }

  private static void assertCleared(Recording key) {
    assertEquals(1, key.handedOut.size());
    assertArrayEquals(new byte[key.handedOut.get(0).length], key.handedOut.get(0));
  }

  private static RawRsaKeyring.Builder rsa() {
    return RawRsaKeyring.builder().keyNamespace("ns").keyName("name").paddingScheme(PaddingScheme.OAEP_SHA256_MGF1);
  }

  private static KeyPair keyPair(String algorithm, String curve) {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
      if (curve == null) {
        generator.initialize(2048);
      } else {
        generator.initialize(new ECGenParameterSpec(curve));
      }
      return generator.generateKeyPair();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static byte[] der(String pem) {
    StringBuilder body = new StringBuilder();
    for (String line : pem.split("\\R")) {
      if (!line.startsWith("-----")) {
        body.append(line.trim());
      }
    }
    return Base64.getDecoder().decode(body.toString());
  }

  private static void assertMessage(String message, Executable call) {
    assertEquals(message, assertThrows(ValidationException.class, call).getMessage());
  }

  // A key held where its bytes cannot be exported, such as a hardware module.
  private static final class Unencoded implements PublicKey, PrivateKey {

    private static final long serialVersionUID = 1L;

    @Override
    public String getAlgorithm() {
      return "RSA";
    }

    @Override
    public String getFormat() {
      return null;
    }

    @Override
    public byte[] getEncoded() {
      return null;
    }
  }

  // Remembers each encoding it hands out, to check the caller cleared it.
  private static final class Recording implements PrivateKey {

    private static final long serialVersionUID = 1L;

    private final PrivateKey key;
    final java.util.List<byte[]> handedOut = new java.util.ArrayList<>();

    Recording(PrivateKey key) {
      this.key = key;
    }

    @Override
    public String getAlgorithm() {
      return key.getAlgorithm();
    }

    @Override
    public String getFormat() {
      return key.getFormat();
    }

    @Override
    public byte[] getEncoded() {
      byte[] encoded = key.getEncoded();
      handedOut.add(encoded);
      return encoded;
    }
  }
}
