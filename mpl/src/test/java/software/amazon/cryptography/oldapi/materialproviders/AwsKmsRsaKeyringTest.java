// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.base64;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.decode;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.grantTokenLists;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.invalidEncryptionMaterials;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.keyIdentifiers;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.remove;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.serviceErrors;
import static software.amazon.cryptography.oldapi.materialproviders.KeyringTests.*;
import static software.amazon.cryptography.oldapi.materialproviders.KmsKeyringTests.*;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.fakeaws.FakeKms;
import software.amazon.cryptography.materialproviders.fakeaws.ServiceError;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Outcomes;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Pair;
import software.amazon.cryptography.oldapi.materialproviders.internal.Convert;
import software.amazon.cryptography.oldapi.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateAwsKmsRsaKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptionMaterials;

// Differential tests of the AWS KMS RSA keyring against the published Dafny-based MPL.
// Encryption is local and randomized (OAEP, data key), so each side decrypts both sides' encrypted data keys;
// both sides call the same fake KMS to decrypt, and outcomes and the KMS requests sent are compared.
class AwsKmsRsaKeyringTest {

  private static final List<EncryptionAlgorithmSpec> OAEP = Arrays.asList(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1, EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256);

  private final Object reference = ReferenceMpl.materialProviders();
  private final Outcomes outcomes = new Outcomes();
  private final FakeAws aws = FakeAws.start();
  private final KmsClient kms = ReferenceAws.kms(aws, REGION);

  @AfterEach
  void close() {
    aws.close();
  }

  // Every combination of public key, client, algorithm, key id, and grant tokens: each check and the order of the checks.
  @Test
  //= spec/framework/aws-kms/aws-kms-rsa-keyring.md#initialization
  //= type=test
  //# The AWS KMS key identifier MUST be [a valid identifier](../../framework/aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-identifier).
  //= spec/framework/aws-kms/aws-kms-rsa-keyring.md#initialization
  //= type=test
  //# If provided the Public Key
  //# MUST have an RSA modulus bit length greater than or equal to 2048.
  void create() {
    String arn = aws.kms().createRsaKey(REGION, "RSA_2048");
    String prefix = arn.substring(0, arn.indexOf("key/"));
    byte[] pem = aws.kms().publicKeyPem(arn).getBytes(StandardCharsets.UTF_8);
    List<byte[]> publicKeys = Arrays.asList(
      null,
      pem,
      aws.kms().publicKeyPem(aws.kms().createRsaKey(REGION, "RSA_4096")).getBytes(StandardCharsets.UTF_8),
      rsaPublicKeyPem(2047),
      rsaPublicKeyPem(1024),
      new byte[0],
      "not a key".getBytes(StandardCharsets.US_ASCII),
      Base64.getMimeDecoder().decode(new String(pem, StandardCharsets.UTF_8).replaceAll("-----[A-Z ]*-----", "")),
      aws.kms().publicKeyPem(aws.kms().createEccKeyAgreementKey(REGION, "ECC_NIST_P256")).getBytes(StandardCharsets.UTF_8)
    );
    // An ARN of exactly 2048 and 2049 characters: the length limit, then ValidateKmsKeyId's.
    List<String> keyIds = Arrays.asList(
      arn,
      prefix + "alias/name",
      "alias/name",
      "",
      prefix + "key/\u00e9",
      prefix + "key/" + repeat('a', 2048 - prefix.length() - 4),
      prefix + "key/" + repeat('a', 2049 - prefix.length() - 4),
      "key/a"
    );
    List<List<String>> grantTokens = Arrays.asList(null, Collections.singletonList("token"), grantTokenLists().get(4));
    for (byte[] publicKey : publicKeys) {
      for (KmsClient client : Arrays.asList(null, kms)) {
        for (EncryptionAlgorithmSpec algorithm : EncryptionAlgorithmSpec.values()) {
          for (String keyId : keyIds) {
            for (List<String> tokens : grantTokens) {
              assertSameCreate(input(publicKey, keyId, algorithm, client, tokens));
            }
          }
        }
      }
    }
    // Every key identifier shape and grant token list, with a valid key and client.
    for (String keyId : keyIdentifiers(arn)) {
      for (List<String> tokens : grantTokenLists()) {
        assertSameCreate(input(pem, keyId, EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256, kms, tokens));
      }
    }
    outcomes.assertBothSeen("CreateAwsKmsRsaKeyring");
  }

  @Test
  void eachSideDecryptsTheOther() {
    for (String keySpec : Arrays.asList("RSA_2048", "RSA_3072", "RSA_4096")) {
      String arn = aws.kms().createRsaKey(REGION, keySpec);
      byte[] pem = aws.kms().publicKeyPem(arn).getBytes(StandardCharsets.UTF_8);
      for (EncryptionAlgorithmSpec algorithm : OAEP) {
        Pair keyring = rsa(pem, arn, algorithm, kms, Arrays.asList("token1", "token2"));
        Pair encryptOnly = rsa(pem, arn, algorithm, null, null);
        Pair decryptOnly = rsa(null, arn, algorithm, kms, null);
        EncryptionAlgorithmSpec otherAlgorithm = OAEP.get(1 - OAEP.indexOf(algorithm));
        Pair otherPadding = rsa(null, arn, otherAlgorithm, kms, null);
        for (AlgorithmSuiteId suite : allSuites()) {
          boolean signing = Convert.suite(suite).isSigning();
          for (Map<String, String> encryptionContext : Arrays.asList(map(), map("a", "b", "\u00fc", "\ud83d\ude00"))) {
            for (boolean withDataKey : new boolean[] { false, true }) {
              EncryptionMaterials start = encryptionMaterials(suite, encryptionContext, withDataKey);
              String context = keySpec + " " + algorithm + " " + ReferenceMpl.describe(suite) + " " + encryptionContext + " data key " + withDataKey;
              assertSameEncrypt(aws, outcomes, keyring, start, context);
              assertSameEncrypt(aws, outcomes, encryptOnly, start, context + " encrypt only");
              assertSameEncrypt(aws, outcomes, decryptOnly, start, context + " decrypt only");
              if (signing) {
                continue;
              }
              for (EncryptionMaterials result : Arrays.asList(keyring.nativeEncrypt(start), keyring.referenceEncrypt(start), encryptOnly.nativeEncrypt(start))) {
                DecryptionMaterials materials = decryptionMaterials(result);
                for (Pair decryptor : Arrays.asList(keyring, decryptOnly)) {
                  String decrypted = assertSameDecrypt(aws, outcomes, decryptor, materials, result.encryptedDataKeys(), context);
                  assertEquals(ReferenceMpl.describe(expectedDecryption(result)), decrypted, context);
                }
                // KMS decrypts with the other padding; the result fails the OAEP check (collected).
                String failed = assertSameDecrypt(aws, outcomes, otherPadding, materials, result.encryptedDataKeys(), context + " other padding");
                assertTrue(failed.startsWith("throws"), context);
                // The encryption context is bound by the digest, not sent to KMS.
                assertSameDecrypt(aws, outcomes, keyring, decryptionMaterials(result, map("a", "c")), result.encryptedDataKeys(), context + " other context");
              }
            }
          }
        }
      }
    }
    outcomes.assertBothSeen("OnEncrypt");
    outcomes.assertBothSeen("OnDecrypt");
  }

  // OAEP and the data key are random: a repeated ciphertext or data key would mean a fixed seed.
  @Test
  void everyEncryptionIsFresh() {
    String arn = aws.kms().createRsaKey(REGION, "RSA_2048");
    Pair keyring = rsa(aws.kms().publicKeyPem(arn).getBytes(StandardCharsets.UTF_8), arn, EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256, kms, null);
    for (AlgorithmSuiteId suite : allSuites()) {
      if (Convert.suite(suite).isSigning()) {
        continue;
      }
      EncryptionMaterials withKey = encryptionMaterials(suite, map("a", "b"), true);
      EncryptedDataKey first = keyring.nativeEncrypt(withKey).encryptedDataKeys().get(0);
      EncryptedDataKey second = keyring.nativeEncrypt(withKey).encryptedDataKeys().get(0);
      assertFalse(Arrays.equals(array(first.ciphertext()), array(second.ciphertext())), "ciphertext repeated");
      EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false);
      assertFalse(Arrays.equals(array(keyring.nativeEncrypt(start).plaintextDataKey()), array(keyring.nativeEncrypt(start).plaintextDataKey())), "data key repeated");
    }
  }

  @Test
  //= spec/framework/aws-kms/aws-kms-rsa-keyring.md#onencrypt
  //= type=test
  //# OnEncrypt MUST fail if the input [encryption materials](../structures.md#encryption-materials)
  //# contains an [algorithm suite](../algorithm-suites.md) containing an
  //# [asymmetric signature](../algorithm-suites.md#asymmetric-signature-algorithm).
  void encryptFailures() {
    String arn = aws.kms().createRsaKey(REGION, "RSA_2048");
    byte[] pem = aws.kms().publicKeyPem(arn).getBytes(StandardCharsets.UTF_8);
    Pair keyring = rsa(pem, arn, EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1, kms, null);
    Pair decryptOnly = rsa(null, arn, EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1, kms, null);
    for (AlgorithmSuiteId suite : allSuites()) {
      List<EncryptionMaterials> inputs = new ArrayList<>(invalidEncryptionMaterials(suite));
      inputs.add(encryptionMaterials(suite, map(repeat('k', 65536), "v"), false));
      inputs.add(encryptionMaterials(suite, map(repeat('k', 65536), "v"), true));
      // Both an unserializable context and invalid materials: pins which check runs first.
      inputs.add(encryptionMaterials(suite, map(repeat('k', 65536), "v"), false).toBuilder().plaintextDataKey(ByteBuffer.wrap(new byte[3])).build());
      for (int i = 0; i < inputs.size(); i++) {
        assertSameEncrypt(aws, outcomes, keyring, inputs.get(i), ReferenceMpl.describe(suite) + " input " + i);
        assertSameEncrypt(aws, outcomes, decryptOnly, inputs.get(i), ReferenceMpl.describe(suite) + " decrypt only, input " + i);
      }
      if (!Convert.suite(suite).isSigning()) {
        EncryptionMaterials encrypted = keyring.nativeEncrypt(encryptionMaterials(suite, map("a", "b"), false));
        assertSameEncrypt(aws, outcomes, keyring, encrypted, ReferenceMpl.describe(suite) + " already encrypted");
      }
    }
    outcomes.assertBothSeen("OnEncrypt");
  }

  @Test
  //= spec/framework/aws-kms/aws-kms-rsa-keyring.md#ondecrypt
  //= type=test
  //# OnDecrypt MUST fail if the input [decryption materials](../structures.md#decryption-materials)
  //# contains an [algorithm suite](../algorithm-suites.md) containing an
  //# [asymmetric signature](../algorithm-suites.md#asymmetric-signature-algorithm).
  void decryptFailures() {
    String arn = aws.kms().createRsaKey(REGION, "RSA_2048");
    String otherArn = aws.kms().createRsaKey(REGION, "RSA_2048");
    String prefix = arn.substring(0, arn.indexOf("key/"));
    aws.kms().createAlias("alias/named", arn);
    byte[] pem = aws.kms().publicKeyPem(arn).getBytes(StandardCharsets.UTF_8);
    byte[] otherPem = aws.kms().publicKeyPem(otherArn).getBytes(StandardCharsets.UTF_8);
    // A multi-Region key name the fake does not have: filtering matches its replicas, KMS then fails (collected).
    String mrkArn = prefix + "key/mrk-1234";
    Map<String, Pair> keyrings = new LinkedHashMap<>();
    keyrings.put("key", rsa(pem, arn, EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256, kms, Collections.singletonList("token")));
    keyrings.put("no client", rsa(pem, arn, EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256, null, null));
    // X2: an alias ARN builds and encrypts, but cannot decrypt.
    keyrings.put("alias ARN", rsa(pem, prefix + "alias/named", EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256, kms, null));
    keyrings.put("other key", rsa(otherPem, otherArn, EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256, kms, null));
    keyrings.put("multi-Region key", rsa(null, mrkArn, EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256, kms, null));
    Pair keyring = keyrings.get("key");
    for (AlgorithmSuiteId suite : allSuites()) {
      String context = ReferenceMpl.describe(suite);
      if (Convert.suite(suite).isSigning()) {
        // The suite check follows the client, materials, and key ARN checks.
        DecryptionMaterials signingMaterials = decryptionMaterials(encryptionMaterials(suite, map("a", "b"), false));
        EncryptedDataKey edk = edk("aws-kms-rsa", arn.getBytes(StandardCharsets.UTF_8), new byte[256]);
        for (Pair decryptor : keyrings.values()) {
          assertSameDecrypt(aws, outcomes, decryptor, signingMaterials, Collections.singletonList(edk), context);
          assertSameDecrypt(aws, outcomes, decryptor, signingMaterials, Collections.singletonList(edk("aws-kms-rsa", new byte[] { (byte) 0xff }, new byte[1])), context);
        }
        continue;
      }
      EncryptionMaterials encrypted = keyring.nativeEncrypt(encryptionMaterials(suite, map("a", "b"), false));
      EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false).toBuilder().plaintextDataKey(encrypted.plaintextDataKey()).build();
      EncryptedDataKey good = encrypted.encryptedDataKeys().get(0);
      EncryptedDataKey other = keyrings.get("other key").nativeEncrypt(start).encryptedDataKeys().get(0);
      byte[] ciphertext = array(good.ciphertext());
      byte[] info = array(good.keyProviderInfo());
      DecryptionMaterials materials = decryptionMaterials(encrypted);
      int prefixLength = Convert.suite(suite).usesIntermediateKeyWrapping() ? array(start.plaintextDataKey()).length + 16 : 0;

      List<List<EncryptedDataKey>> edkLists = new ArrayList<>();
      edkLists.add(Collections.emptyList());
      edkLists.add(Collections.singletonList(good));
      edkLists.add(Collections.singletonList(other));
      edkLists.add(Arrays.asList(other, good));
      edkLists.add(Arrays.asList(good, other));
      edkLists.add(Collections.singletonList(edk("aws-kms", info, ciphertext)));
      edkLists.add(Collections.singletonList(edk("aws-kms-rsa ", info, ciphertext)));
      edkLists.add(Collections.singletonList(edk("raw", new byte[] { (byte) 0xff }, ciphertext)));
      edkLists.add(Arrays.asList(edk("raw", new byte[] { 'k', (byte) 0x80, 0, 0 }, ciphertext), good));
      edkLists.add(Arrays.asList(good, edk("aws-kms-rsa", new byte[] { (byte) 0xff }, ciphertext)));
      edkLists.add(Collections.singletonList(edk("aws-kms-rsa", new byte[] { (byte) 0xed, (byte) 0xa0, (byte) 0x80 }, ciphertext)));
      for (String providerInfo : Arrays.asList(
        "not an arn",
        prefix + "alias/named",
        "key/abc",
        prefix + "key/",
        arn.replace(REGION, OTHER_REGION),
        arn.replace(FakeKms.ACCOUNT, "444455556666"),
        mrkArn.replace(REGION, OTHER_REGION),
        mrkArn.replace("arn:aws:", "arn:aws-cn:"),
        mrkArn + "5"
      )) {
        edkLists.add(Collections.singletonList(edk("aws-kms-rsa", providerInfo.getBytes(StandardCharsets.UTF_8), ciphertext)));
      }
      for (int length : new int[] { 0, 43, 44, 47, 48, 48 + 43, 48 + 44, 100 }) {
        edkLists.add(Collections.singletonList(edk("aws-kms-hierarchy", "branch".getBytes(StandardCharsets.UTF_8), bytes(length, 7))));
      }
      edkLists.add(Collections.singletonList(edk("aws-kms-rsa", info, array(other.ciphertext()))));
      edkLists.add(Collections.singletonList(edk("aws-kms-rsa", info, flip(ciphertext, ciphertext.length - 1))));
      edkLists.add(Arrays.asList(edk("aws-kms-rsa", info, flip(ciphertext, ciphertext.length - 1)), good));
      for (int length : new int[] { 0, 1, prefixLength - 1, prefixLength, prefixLength + 1, ciphertext.length - 1 }) {
        if (length >= 0) {
          edkLists.add(Collections.singletonList(edk("aws-kms-rsa", info, Arrays.copyOf(ciphertext, length))));
        }
      }
      edkLists.add(Collections.singletonList(edk("aws-kms-rsa", info, Arrays.copyOf(ciphertext, prefixLength + 6144))));
      edkLists.add(Collections.singletonList(edk("aws-kms-rsa", info, Arrays.copyOf(ciphertext, prefixLength + 6145))));

      for (Map.Entry<String, Pair> decryptor : keyrings.entrySet()) {
        for (List<EncryptedDataKey> edks : edkLists) {
          assertSameDecrypt(aws, outcomes, decryptor.getValue(), materials, edks, decryptor.getKey() + " " + context);
        }
      }
      List<EncryptedDataKey> goodOnly = Collections.singletonList(good);
      for (Map.Entry<String, ServiceError> error : serviceErrors().entrySet()) {
        aws.kms().fail("Decrypt", null, error.getValue());
        assertSameDecrypt(aws, outcomes, keyring, materials, goodOnly, context + " " + error.getKey());
        assertSameDecrypt(aws, outcomes, keyring, materials, Arrays.asList(good, good), context + " twice " + error.getKey());
        aws.kms().clearFailures();
      }
      Map<String, UnaryOperator<ObjectNode>> edits = new LinkedHashMap<>();
      edits.put("no KeyId", r -> remove(r, "KeyId"));
      edits.put("other KeyId", r -> r.put("KeyId", otherArn));
      edits.put("no Plaintext", r -> remove(r, "Plaintext"));
      edits.put("empty Plaintext", r -> r.put("Plaintext", ""));
      edits.put("short Plaintext", r -> r.put("Plaintext", base64(Arrays.copyOf(decode(r, "Plaintext"), decode(r, "Plaintext").length - 1))));
      edits.put("long Plaintext", r -> r.put("Plaintext", base64(Arrays.copyOf(decode(r, "Plaintext"), decode(r, "Plaintext").length + 1))));
      edits.put("digest only", r -> r.put("Plaintext", base64(Arrays.copyOf(decode(r, "Plaintext"), 48))));
      edits.put("digest flipped", r -> r.put("Plaintext", base64(flip(decode(r, "Plaintext"), 0))));
      edits.put("digest last byte flipped", r -> r.put("Plaintext", base64(flip(decode(r, "Plaintext"), 47))));
      edits.put("data key flipped", r -> r.put("Plaintext", base64(flip(decode(r, "Plaintext"), 48))));
      for (Map.Entry<String, UnaryOperator<ObjectNode>> edit : edits.entrySet()) {
        aws.kms().editResponses("Decrypt", edit.getValue());
        assertSameDecrypt(aws, outcomes, keyring, materials, goodOnly, context + " " + edit.getKey());
        aws.kms().clearFailures();
      }
      // Materials: other or unserializable context, invalid, already holding a data key; combined with keys that fail to filter or match.
      DecryptionMaterials unserializable = decryptionMaterials(encrypted, map(repeat('k', 65536), "v"));
      DecryptionMaterials missingRequired = materials.toBuilder().requiredEncryptionContextKeys(Collections.singletonList("missing")).build();
      DecryptionMaterials decrypted = keyring.nativeDecrypt(materials, goodOnly);
      for (DecryptionMaterials otherMaterials : Arrays.asList(decryptionMaterials(encrypted, map("a", "c")), decryptionMaterials(encrypted, map()), unserializable, missingRequired, decrypted)) {
        for (Map.Entry<String, Pair> decryptor : keyrings.entrySet()) {
          for (List<EncryptedDataKey> edks : Arrays.asList(goodOnly, Collections.<EncryptedDataKey>emptyList(), Collections.singletonList(edk("aws-kms-rsa", new byte[] { (byte) 0xff }, ciphertext)))) {
            assertSameDecrypt(aws, outcomes, decryptor.getValue(), otherMaterials, edks, decryptor.getKey() + " " + context + " other materials");
          }
        }
      }
    }
    outcomes.assertBothSeen("OnDecrypt");
  }

  // The digest the KMS plaintext starts with is SHA-384 of the serialized context: checked against an independent computation.
  @Test
  //= spec/framework/aws-kms/aws-kms-rsa-keyring.md#onencrypt
  //= type=test
  //# OnEncrypt MUST calculate a Encryption Context Digest by:
  void digestIsSha384OfTheSerializedContext() throws GeneralSecurityException {
    String arn = aws.kms().createRsaKey(REGION, "RSA_2048");
    Pair keyring = rsa(aws.kms().publicKeyPem(arn).getBytes(StandardCharsets.UTF_8), arn, EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256, kms, null);
    AlgorithmSuiteId suite = allSuites().get(0);
    EncryptionMaterials encrypted = keyring.nativeEncrypt(encryptionMaterials(suite, map("b", "2", "a", "1"), true));
    byte[][] seen = new byte[1][];
    aws.kms().editResponses("Decrypt", r -> {
      seen[0] = decode(r, "Plaintext");
      return r;
    });
    keyring.nativeDecrypt(decryptionMaterials(encrypted), encrypted.encryptedDataKeys());
    byte[] serialized = { 0, 2, 0, 1, 'a', 0, 1, '1', 0, 1, 'b', 0, 1, '2' };
    byte[] expected = MessageDigest.getInstance("SHA-384").digest(serialized);
    assertEquals(ReferenceMpl.describe(ByteBuffer.wrap(expected)), ReferenceMpl.describe(ByteBuffer.wrap(Arrays.copyOf(seen[0], 48))));
    assertEquals(ReferenceMpl.describe(encrypted.plaintextDataKey()), ReferenceMpl.describe(ByteBuffer.wrap(Arrays.copyOfRange(seen[0], 48, seen[0].length))));
  }

  // The Dafny-based MPL converted each KMS response field to its own types, so a value the SDK did not know failed the call
  // even in a field the keyring never reads; the native keyring reads the SDK response and does not look at that field.
  @Test
  void unknownEnumValueInADecryptResponse() {
    String arn = aws.kms().createRsaKey(REGION, "RSA_2048");
    Pair keyring = rsa(aws.kms().publicKeyPem(arn).getBytes(StandardCharsets.UTF_8), arn, EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256, kms, null);
    EncryptionMaterials encrypted = keyring.nativeEncrypt(encryptionMaterials(allSuites().get(0), map("a", "b"), false));
    DecryptionMaterials materials = decryptionMaterials(encrypted);
    aws.kms().editResponses("Decrypt", r -> r.put("EncryptionAlgorithm", "SOMETHING_NEW"));
    String expected = ReferenceMpl.outcome(() -> ReferenceMpl.call(keyring.referenceKeyring, "OnDecrypt", decryptInput(materials, encrypted.encryptedDataKeys())));
    String actual = ReferenceMpl.outcome(() -> keyring.nativeDecrypt(materials, encrypted.encryptedDataKeys()));
    aws.kms().clearFailures();
    assertTrue(expected.contains("Cannot convert null to software.amazon.cryptography.services.kms.internaldafny.types.EncryptionAlgorithmSpec."), expected);
    assertEquals(ReferenceMpl.describe(expectedDecryption(encrypted).materials()), actual);
  }

  private void assertSameCreate(CreateAwsKmsRsaKeyringInput input) {
    assertSame(
      aws,
      outcomes,
      "CreateAwsKmsRsaKeyring",
      () -> AwsKmsKeyringTest.created(ReferenceMpl.call(reference, "CreateAwsKmsRsaKeyring", input)),
      () -> AwsKmsKeyringTest.created(MPL.CreateAwsKmsRsaKeyring(input)),
      ReferenceMpl.describe(input)
    );
  }

  private Pair rsa(byte[] publicKey, String keyId, EncryptionAlgorithmSpec algorithm, KmsClient client, List<String> grantTokens) {
    CreateAwsKmsRsaKeyringInput input = input(publicKey, keyId, algorithm, client, grantTokens);
    return new Pair(MPL.CreateAwsKmsRsaKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsRsaKeyring", input));
  }

  private static CreateAwsKmsRsaKeyringInput input(byte[] publicKey, String keyId, EncryptionAlgorithmSpec algorithm, KmsClient client, List<String> grantTokens) {
    return CreateAwsKmsRsaKeyringInput
      .builder()
      .publicKey(publicKey == null ? null : ByteBuffer.wrap(publicKey))
      .kmsKeyId(keyId)
      .encryptionAlgorithm(algorithm)
      .kmsClient(client)
      .grantTokens(grantTokens)
      .build();
  }

  private static byte[] rsaPublicKeyPem(int bits) {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(bits);
      String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(generator.generateKeyPair().getPublic().getEncoded());
      return ("-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----\n").getBytes(StandardCharsets.US_ASCII);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }
}
