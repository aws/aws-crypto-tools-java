// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.materialproviders.KeyringTests.array;
import static software.amazon.cryptography.materialproviders.KeyringTests.decryptionMaterials;
import static software.amazon.cryptography.materialproviders.KeyringTests.edk;
import static software.amazon.cryptography.materialproviders.KeyringTests.encryptionMaterials;
import static software.amazon.cryptography.materialproviders.KeyringTests.flip;
import static software.amazon.cryptography.materialproviders.KeyringTests.map;
import static software.amazon.cryptography.materialproviders.RealChecks.KMS;
import static software.amazon.cryptography.materialproviders.RealChecks.assertCmmRoundTrip;
import static software.amazon.cryptography.materialproviders.RealChecks.assertEachDecrypts;
import static software.amazon.cryptography.materialproviders.RealChecks.assertEachFails;
import static software.amazon.cryptography.materialproviders.RealChecks.assertSameDecrypt;
import static software.amazon.cryptography.materialproviders.RealChecks.assertSameEncrypt;
import static software.amazon.cryptography.materialproviders.RealChecks.binaryInfo;
import static software.amazon.cryptography.materialproviders.RealChecks.encryptedByBoth;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.cryptography.materialproviders.KeyringTests.Outcomes;
import software.amazon.cryptography.materialproviders.KeyringTests.Pair;
import software.amazon.cryptography.materialproviders.RawEcdhKeyringTest.Keys;
import software.amazon.cryptography.materialproviders.RealChecks.Mask;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsEcdhKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsRsaKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRawEcdhKeyringInput;
import software.amazon.cryptography.materialproviders.model.DBEAlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.model.EphemeralPrivateKeyToStaticPublicKeyInput;
import software.amazon.cryptography.materialproviders.model.KmsEcdhStaticConfigurations;
import software.amazon.cryptography.materialproviders.model.KmsPrivateKeyToStaticPublicKeyInput;
import software.amazon.cryptography.materialproviders.model.KmsPublicKeyDiscoveryInput;
import software.amazon.cryptography.materialproviders.model.PublicKeyDiscoveryInput;
import software.amazon.cryptography.materialproviders.model.RawEcdhStaticConfigurations;
import software.amazon.cryptography.materialproviders.model.RawPrivateKeyToStaticPublicKeyInput;
import software.amazon.cryptography.primitives.model.ECDHCurveSpec;

// The KMS RSA keyring and the KMS ECDH keyring, native and reference, against real KMS keys
// (RSA_2048 ENCRYPT_DECRYPT, ECC_NIST_P256 KEY_AGREEMENT).
// Encryption is randomized, so each side decrypts both sides' encrypted data keys.
class RealKmsAsymmetricKeyringsIT {

  private static final ECDHCurveSpec P256 = ECDHCurveSpec.ECC_NIST_P256;
  private static final List<EncryptionAlgorithmSpec> OAEP = Arrays.asList(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1, EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256);
  // The KMS RSA keyring refuses signing suites, so a DB-ESDK suite without ECDSA is added for it.
  private static final AlgorithmSuiteId DBE_NOT_SIGNING = AlgorithmSuiteId
    .builder()
    .DBE(DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384)
    .build();

  private static RealAws aws;
  private static KmsClient kms;
  private static KmsClient replicaKms;

  private final Object reference = ReferenceMpl.materialProviders();
  private final Outcomes outcomes = new Outcomes();

  @BeforeAll
  static void clients() {
    aws = RealAws.fromEnvironment();
    kms = aws.kms(aws.region);
    replicaKms = aws.kms(aws.replicaRegion);
  }

  @AfterAll
  static void close() {
    aws.close();
  }

  @Test
  void rsaEachSideDecryptsTheOther() {
    byte[] pem = pem(publicKey(aws.rsa));
    List<AlgorithmSuiteId> suites = new ArrayList<>(RealAws.SUITES);
    suites.add(DBE_NOT_SIGNING);
    for (EncryptionAlgorithmSpec algorithm : OAEP) {
      Pair keyring = rsa(pem, aws.rsa, algorithm, kms);
      Pair encryptOnly = rsa(pem, aws.rsa, algorithm, null);
      Pair decryptOnly = rsa(null, aws.rsa, algorithm, kms);
      Pair otherPadding = rsa(null, aws.rsa, OAEP.get(1 - OAEP.indexOf(algorithm)), kms);
      Pair otherRegion = rsa(null, aws.rsa, algorithm, replicaKms);
      for (AlgorithmSuiteId suite : suites) {
        for (boolean withDataKey : new boolean[] { false, true }) {
          EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), withDataKey);
          String context = algorithm + " " + ReferenceMpl.describe(suite) + " data key " + withDataKey;
          assertSameEncrypt(outcomes, decryptOnly, start, KMS, context + " decrypt only");
          if (assertSameEncrypt(outcomes, keyring, start, KMS, context).startsWith("throws")) {
            continue;
          }
          List<EncryptionMaterials> results = new ArrayList<>(encryptedByBoth(keyring, start));
          results.addAll(encryptedByBoth(encryptOnly, start));
          assertEachDecrypts(outcomes, results, Arrays.asList(keyring, decryptOnly), context);
          assertEachFails(outcomes, results, Arrays.asList(otherPadding, otherRegion, encryptOnly), context);
          for (EncryptionMaterials result : results) {
            // The encryption context is bound by the OAEP label digest, not sent to KMS.
            String failed = assertSameDecrypt(outcomes, keyring, decryptionMaterials(result, map("a", "c")), result.encryptedDataKeys(), context + " other context");
            assertTrue(failed.startsWith("throws"), failed);
          }
        }
        if (!suite.equals(RealAws.COMMITTING_SIGNING) && !suite.equals(RealAws.DBE)) {
          assertCmmRoundTrip(reference, outcomes, keyring, decryptOnly, suite, KMS, "RSA " + algorithm);
        }
      }
    }
    outcomes.assertBothSeen("OnEncrypt");
    outcomes.assertBothSeen("OnDecrypt");
  }

  // What real KMS refuses for RSA: malformed ciphertext, ciphertext for another public key,
  // and a symmetric key asked to decrypt with an RSA algorithm.
  @Test
  void rsaKmsFailures() throws GeneralSecurityException {
    byte[] pem = pem(publicKey(aws.rsa));
    Pair keyring = rsa(pem, aws.rsa, EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256, kms);
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    Pair otherPublicKey = rsa(pem(generator.generateKeyPair().getPublic().getEncoded()), aws.rsa, EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256, null);
    Pair symmetric = rsa(null, aws.sym, EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256, kms);
    for (AlgorithmSuiteId suite : Arrays.asList(RealAws.NON_COMMITTING, DBE_NOT_SIGNING)) {
      String label = ReferenceMpl.describe(suite);
      EncryptionMaterials encrypted = keyring.nativeEncrypt(encryptionMaterials(suite, map("a", "b"), false));
      EncryptedDataKey good = encrypted.encryptedDataKeys().get(0);
      byte[] ciphertext = array(good.ciphertext());
      byte[] info = array(good.keyProviderInfo());
      DecryptionMaterials materials = decryptionMaterials(encrypted);
      Map<String, List<EncryptedDataKey>> edkLists = new LinkedHashMap<>();
      edkLists.put("last byte flipped", Collections.singletonList(edk("aws-kms-rsa", info, flip(ciphertext, ciphertext.length - 1))));
      edkLists.put("first byte flipped", Collections.singletonList(edk("aws-kms-rsa", info, flip(ciphertext, 0))));
      edkLists.put("truncated", Collections.singletonList(edk("aws-kms-rsa", info, Arrays.copyOf(ciphertext, 255))));
      edkLists.put("empty", Collections.singletonList(edk("aws-kms-rsa", info, new byte[0])));
      edkLists.put("for another public key", otherPublicKey.nativeEncrypt(encryptionMaterials(suite, map("a", "b"), false)).encryptedDataKeys());
      for (Map.Entry<String, List<EncryptedDataKey>> edks : edkLists.entrySet()) {
        String failed = assertSameDecrypt(outcomes, keyring, materials, edks.getValue(), label + " " + edks.getKey());
        assertTrue(failed.startsWith("throws"), failed);
      }
      List<EncryptedDataKey> forSymmetric = Collections.singletonList(edk("aws-kms-rsa", aws.sym.getBytes(StandardCharsets.UTF_8), ciphertext));
      String failed = assertSameDecrypt(outcomes, symmetric, materials, forSymmetric, label + " symmetric key");
      assertTrue(failed.startsWith("throws"), failed);
    }
  }

  @Test
  void ecdhEachSideDecryptsTheOther() {
    byte[] eccPublic = publicKey(aws.ecc);
    Keys local = Keys.of("testVectorKeys", P256);
    Pair toItself = kmsEcdh(kmsPrivate(aws.ecc, null, eccPublic), kms);
    Pair toItselfWithKey = kmsEcdh(kmsPrivate(aws.ecc, eccPublic, eccPublic), kms);
    Pair toLocal = kmsEcdh(kmsPrivate(aws.ecc, null, local.senderPublic), kms);
    Pair discovery = kmsEcdh(discovery(aws.ecc), kms);
    Pair localToKms = rawEcdh(
      RawEcdhStaticConfigurations
        .builder()
        .RawPrivateKeyToStaticPublicKey(
          RawPrivateKeyToStaticPublicKeyInput.builder().senderStaticPrivateKey(ByteBuffer.wrap(local.senderPrivate)).recipientPublicKey(ByteBuffer.wrap(eccPublic)).build()
        )
        .build()
    );
    Pair ephemeralToKms = rawEcdh(
      RawEcdhStaticConfigurations
        .builder()
        .EphemeralPrivateKeyToStaticPublicKey(EphemeralPrivateKeyToStaticPublicKeyInput.builder().recipientPublicKey(ByteBuffer.wrap(eccPublic)).build())
        .build()
    );
    Pair localDiscovery = rawEcdh(
      RawEcdhStaticConfigurations
        .builder()
        .PublicKeyDiscovery(PublicKeyDiscoveryInput.builder().recipientStaticPrivateKey(ByteBuffer.wrap(local.senderPrivate)).build())
        .build()
    );
    // A static keyring whose public key is given makes its first KMS call when it derives the secret.
    Pair otherRegion = kmsEcdh(kmsPrivate(aws.ecc, eccPublic, eccPublic), replicaKms);

    Map<String, Pair> encryptors = new LinkedHashMap<>();
    Map<Pair, List<List<Pair>>> cases = new LinkedHashMap<>();
    encryptors.put("KMS key to itself", toItself);
    cases.put(toItself, Arrays.asList(Arrays.asList(toItself, toItselfWithKey, discovery), Arrays.asList(toLocal, localDiscovery, otherRegion)));
    encryptors.put("KMS key to itself, public key given", toItselfWithKey);
    cases.put(toItselfWithKey, Arrays.asList(Arrays.asList(toItself, discovery), Collections.singletonList(toLocal)));
    encryptors.put("KMS key to a local key", toLocal);
    cases.put(toLocal, Arrays.asList(Arrays.asList(toLocal, localDiscovery), Arrays.asList(discovery, toItself)));
    encryptors.put("local key to the KMS key", localToKms);
    cases.put(localToKms, Arrays.asList(Arrays.asList(toLocal, discovery), Collections.singletonList(toItself)));
    encryptors.put("ephemeral key to the KMS key", ephemeralToKms);
    cases.put(ephemeralToKms, Arrays.asList(Collections.singletonList(discovery), Arrays.asList(toLocal, toItself)));
    for (Map.Entry<String, Pair> encryptor : encryptors.entrySet()) {
      Mask mask = binaryInfo(encryptor.getValue() == ephemeralToKms ? RawEcdhKeyringTest.compressedLength(P256) : 0);
      for (AlgorithmSuiteId suite : RealAws.SUITES) {
        for (boolean withDataKey : new boolean[] { false, true }) {
          EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), withDataKey);
          String context = encryptor.getKey() + " " + ReferenceMpl.describe(suite) + " data key " + withDataKey;
          assertSameEncrypt(outcomes, encryptor.getValue(), start, mask, context);
          List<EncryptionMaterials> results = encryptedByBoth(encryptor.getValue(), start);
          assertEachDecrypts(outcomes, results, cases.get(encryptor.getValue()).get(0), context);
          assertEachFails(outcomes, results, cases.get(encryptor.getValue()).get(1), context);
        }
        assertCmmRoundTrip(reference, outcomes, encryptor.getValue(), cases.get(encryptor.getValue()).get(0).get(0), suite, mask, encryptor.getKey());
      }
    }
    outcomes.assertBothSeen("OnDecrypt");
  }

  // What real KMS refuses for ECDH: keys of the wrong type or usage, a key ARN of another Region,
  // and keyrings that derive a secret through the wrong client.
  @Test
  void ecdhKmsFailures() {
    byte[] eccPublic = publicKey(aws.ecc);
    Map<String, CreateAwsKmsEcdhKeyringInput> creates = new LinkedHashMap<>();
    creates.put("discovery", input(discovery(aws.ecc), kms));
    creates.put("static", input(kmsPrivate(aws.ecc, null, eccPublic), kms));
    creates.put("discovery, symmetric key", input(discovery(aws.sym), kms));
    creates.put("discovery, RSA key", input(discovery(aws.rsa), kms));
    creates.put("discovery, other Region", input(discovery(aws.ecc), replicaKms));
    creates.put("static, symmetric sender", input(kmsPrivate(aws.sym, null, eccPublic), kms));
    creates.put("static, RSA sender", input(kmsPrivate(aws.rsa, null, eccPublic), kms));
    creates.put("static, other Region", input(kmsPrivate(aws.ecc, null, eccPublic), replicaKms));
    creates.put("static, RSA recipient", input(kmsPrivate(aws.ecc, null, publicKey(aws.rsa)), kms));
    // GetPublicKey answers with the key ARN, which the keyring requires to equal the configured identifier.
    creates.put("static, key id", input(kmsPrivate(RealAws.keyId(aws.ecc), null, eccPublic), kms));
    for (Map.Entry<String, CreateAwsKmsEcdhKeyringInput> create : creates.entrySet()) {
      RealAws.assertSame(
        outcomes,
        "CreateAwsKmsEcdhKeyring",
        () -> AwsKmsKeyringTest.created(ReferenceMpl.call(reference, "CreateAwsKmsEcdhKeyring", create.getValue())),
        () -> AwsKmsKeyringTest.created(KeyringTests.MPL.CreateAwsKmsEcdhKeyring(create.getValue())),
        create.getKey()
      );
    }
    outcomes.assertBothSeen("CreateAwsKmsEcdhKeyring");

    Pair keyring = kmsEcdh(kmsPrivate(aws.ecc, null, eccPublic), kms);
    // Sender keys given, so creation makes no KMS call; the secret is derived with the wrong key or Region.
    Map<String, Pair> deriveFails = new LinkedHashMap<>();
    deriveFails.put("other Region", kmsEcdh(kmsPrivate(aws.ecc, eccPublic, eccPublic), replicaKms));
    deriveFails.put("symmetric key as the sender", kmsEcdh(kmsPrivate(aws.sym, eccPublic, eccPublic), kms));
    deriveFails.put("RSA key as the sender", kmsEcdh(kmsPrivate(aws.rsa, eccPublic, eccPublic), kms));
    for (AlgorithmSuiteId suite : RealAws.SUITES) {
      String label = ReferenceMpl.describe(suite);
      for (Map.Entry<String, Pair> failing : deriveFails.entrySet()) {
        String failed = assertSameEncrypt(outcomes, failing.getValue(), encryptionMaterials(suite, map("a", "b"), false), binaryInfo(0), label + " " + failing.getKey());
        assertTrue(failed.startsWith("throws"), failed);
      }
      EncryptionMaterials encrypted = keyring.nativeEncrypt(encryptionMaterials(suite, map("a", "b"), false));
      DecryptionMaterials materials = decryptionMaterials(encrypted);
      for (Map.Entry<String, Pair> failing : deriveFails.entrySet()) {
        String failed = assertSameDecrypt(outcomes, failing.getValue(), materials, encrypted.encryptedDataKeys(), label + " " + failing.getKey());
        assertTrue(failed.startsWith("throws"), failed);
      }
      EncryptedDataKey good = encrypted.encryptedDataKeys().get(0);
      byte[] ciphertext = array(good.ciphertext());
      byte[] info = array(good.keyProviderInfo());
      Map<String, List<EncryptedDataKey>> edkLists = new LinkedHashMap<>();
      edkLists.put("last byte flipped", Collections.singletonList(edk("aws-kms-ecdh", info, flip(ciphertext, ciphertext.length - 1))));
      edkLists.put("truncated", Collections.singletonList(edk("aws-kms-ecdh", info, Arrays.copyOf(ciphertext, 40))));
      edkLists.put("sender key flipped", Collections.singletonList(edk("aws-kms-ecdh", flip(info, info.length - 1), ciphertext)));
      for (Pair decryptor : Arrays.asList(keyring, kmsEcdh(discovery(aws.ecc), kms))) {
        for (Map.Entry<String, List<EncryptedDataKey>> edks : edkLists.entrySet()) {
          String failed = assertSameDecrypt(outcomes, decryptor, materials, edks.getValue(), label + " " + edks.getKey());
          assertTrue(failed.startsWith("throws"), failed);
        }
        String otherContext = assertSameDecrypt(outcomes, decryptor, decryptionMaterials(encrypted, map("a", "c")), encrypted.encryptedDataKeys(), label + " other context");
        assertTrue(otherContext.startsWith("throws"), otherContext);
        assertFalse(assertSameDecrypt(outcomes, decryptor, materials, encrypted.encryptedDataKeys(), label).startsWith("throws"));
      }
    }
  }

  private byte[] publicKey(String arn) {
    return kms.getPublicKey(r -> r.keyId(arn)).publicKey().asByteArray();
  }

  private static byte[] pem(byte[] der) {
    String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
    return ("-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----\n").getBytes(StandardCharsets.US_ASCII);
  }

  private Pair rsa(byte[] publicKey, String keyId, EncryptionAlgorithmSpec algorithm, KmsClient client) {
    CreateAwsKmsRsaKeyringInput input = CreateAwsKmsRsaKeyringInput
      .builder()
      .publicKey(publicKey == null ? null : ByteBuffer.wrap(publicKey))
      .kmsKeyId(keyId)
      .encryptionAlgorithm(algorithm)
      .kmsClient(client)
      .build();
    return new Pair(KeyringTests.MPL.CreateAwsKmsRsaKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsRsaKeyring", input));
  }

  private Pair kmsEcdh(KmsEcdhStaticConfigurations scheme, KmsClient client) {
    CreateAwsKmsEcdhKeyringInput input = input(scheme, client);
    return new Pair(KeyringTests.MPL.CreateAwsKmsEcdhKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsEcdhKeyring", input));
  }

  private Pair rawEcdh(RawEcdhStaticConfigurations scheme) {
    CreateRawEcdhKeyringInput input = CreateRawEcdhKeyringInput.builder().curveSpec(P256).KeyAgreementScheme(scheme).build();
    return new Pair(KeyringTests.MPL.CreateRawEcdhKeyring(input), ReferenceMpl.call(reference, "CreateRawEcdhKeyring", input));
  }

  private static CreateAwsKmsEcdhKeyringInput input(KmsEcdhStaticConfigurations scheme, KmsClient client) {
    return CreateAwsKmsEcdhKeyringInput.builder().curveSpec(P256).KeyAgreementScheme(scheme).kmsClient(client).build();
  }

  private static KmsEcdhStaticConfigurations discovery(String recipient) {
    return KmsEcdhStaticConfigurations.builder().KmsPublicKeyDiscovery(KmsPublicKeyDiscoveryInput.builder().recipientKmsIdentifier(recipient).build()).build();
  }

  private static KmsEcdhStaticConfigurations kmsPrivate(String sender, byte[] senderPublicKey, byte[] recipientPublicKey) {
    return KmsEcdhStaticConfigurations
      .builder()
      .KmsPrivateKeyToStaticPublicKey(
        KmsPrivateKeyToStaticPublicKeyInput
          .builder()
          .senderKmsIdentifier(sender)
          .senderPublicKey(senderPublicKey == null ? null : ByteBuffer.wrap(senderPublicKey))
          .recipientPublicKey(ByteBuffer.wrap(recipientPublicKey))
          .build()
      )
      .build();
  }
}
