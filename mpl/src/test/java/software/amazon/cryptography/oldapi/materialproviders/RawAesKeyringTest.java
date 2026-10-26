// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.oldapi.materialproviders.KeyringTests.*;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.internal.CanonicalEncryptionContext;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Outcomes;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Pair;
import software.amazon.cryptography.oldapi.materialproviders.model.AesWrappingAlg;
import software.amazon.cryptography.oldapi.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateRawAesKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptionMaterials;

// Differential tests of the Raw AES keyring against the published Dafny-based MPL.
// Encryption is randomized (IV, data key), so each side decrypts both sides' encrypted data keys;
// decryption and every failure are deterministic and compared exactly.
class RawAesKeyringTest {

  private static final String NAMESPACE = "namespace";
  private static final String NAME = "name";

  private final Object reference = ReferenceMpl.materialProviders();
  private final Outcomes outcomes = new Outcomes();

  @Test
  //= spec/framework/raw-aes-keyring.md#changelog
  //= type=test
  //# Raw AES keyring MUST NOT accept a key namespace of "aws-kms".
  //= spec/framework/raw-aes-keyring.md#wrapping-key
  //= type=test
  //# The length
  //# of the wrapping key MUST be 128, 192, or 256.
  void create() {
    String surrogate = "a\uD800b";
    String longest = repeat('n', 65535);
    String tooLong = repeat('n', 65536);
    // Two bytes in UTF-8 each: the limit is on bytes, not characters.
    String tooLongEncoded = repeat('\u00e9', 32768);
    List<CreateRawAesKeyringInput> inputs = new ArrayList<>();
    for (String namespace : Arrays.asList(NAMESPACE, "aws-kms", "aws-kms-x", "", surrogate, longest, tooLong, tooLongEncoded)) {
      inputs.add(input(namespace, NAME, 32, AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16));
    }
    for (String name : Arrays.asList("", surrogate, longest, tooLong, tooLongEncoded)) {
      inputs.add(input(NAMESPACE, name, 32, AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16));
    }
    // Check order: namespace before name before key.
    inputs.add(input("aws-kms", surrogate, 3, AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16));
    inputs.add(input(surrogate, surrogate, 3, AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16));
    inputs.add(input(tooLong, surrogate, 3, AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16));
    inputs.add(input(NAMESPACE, tooLong, 3, AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16));
    for (AesWrappingAlg alg : AesWrappingAlg.values()) {
      for (int keyLength : new int[] { 0, 15, 16, 24, 32, 33 }) {
        inputs.add(input(NAMESPACE, NAME, keyLength, alg));
      }
    }
    CreateRawAesKeyringInput positioned = input(NAMESPACE, NAME, 32, AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16);
    ByteBuffer key = ByteBuffer.wrap(bytes(40, 1));
    key.limit(32);
    key.position(8);
    inputs.add(positioned.toBuilder().wrappingKey(key).build());
    for (CreateRawAesKeyringInput input : inputs) {
      assertSameOutcome(
        "CreateRawAesKeyring",
        () -> created(ReferenceMpl.call(reference, "CreateRawAesKeyring", input)),
        () -> created(MPL.CreateRawAesKeyring(input))
      );
    }
    outcomes.assertBothSeen("CreateRawAesKeyring");
  }

  @Test
  //= spec/framework/raw-aes-keyring.md#onencrypt
  //= type=test
  //# If the [encryption materials](structures.md#encryption-materials) do
  //# not contain a plaintext data key, OnEncrypt MUST generate a random
  //# plaintext data key and set it on the [encryption materials]
  //# (structures.md#encryption-materials).
  //= spec/framework/raw-aes-keyring.md#onencrypt
  //= type=test
  //# OnEncrypt MUST output the modified [encryption materials]
  //# (structures.md#encryption-materials).
  //= spec/framework/raw-aes-keyring.md#onencrypt
  //= type=test
  //# The keyring MUST append the constructed encrypted data key to the
  //# encrypted data key list in the [encryption materials]
  //# (structures.md#encryption-materials).
  //= spec/framework/raw-aes-keyring.md#onencrypt
  //= type=test
  //# The keyring MUST encrypt the plaintext data key in the [encryption
  //# materials](structures.md#encryption-materials) using AES-GCM.
  //= spec/framework/raw-aes-keyring.md#ondecrypt
  //= type=test
  //# If a decryption succeeds, this keyring MUST add the resulting
  //# plaintext data key to the decryption materials and return the
  //# modified materials.
  void eachSideDecryptsTheOther() {
    for (AesWrappingAlg alg : AesWrappingAlg.values()) {
      CreateRawAesKeyringInput keyringInput = input(NAMESPACE, NAME, keyLength(alg), alg);
      Pair keyrings = aes(keyringInput);
      for (AlgorithmSuiteId suite : allSuites()) {
        for (Map<String, String> encryptionContext : Arrays.asList(map(), map("a", "b", "\u00fc", "\ud83d\ude00"))) {
          for (boolean withDataKey : new boolean[] { false, true }) {
            EncryptionMaterials start = encryptionMaterials(suite, encryptionContext, withDataKey);
            EncryptionMaterials nativeResult = keyrings.nativeEncrypt(start);
            EncryptionMaterials referenceResult = keyrings.referenceEncrypt(start);
            String context = alg + " " + ReferenceMpl.describe(suite) + " " + encryptionContext + " data key " + withDataKey;
            assertEquals(masked(referenceResult, withDataKey), masked(nativeResult, withDataKey), context);
            assertTrue(!iv(nativeResult).equals(iv(keyrings.nativeEncrypt(start))), "IV repeated: " + context);
            for (EncryptionMaterials result : Arrays.asList(nativeResult, referenceResult)) {
              String decrypted = keyrings.assertSameDecrypt(outcomes, decryptionMaterials(result), result.encryptedDataKeys(), context);
              assertEquals(ReferenceMpl.describe(expectedDecryption(result)), decrypted, context);
            }
          }
        }
      }
    }
  }

  @Test
  //= spec/framework/raw-aes-keyring.md#ondecrypt
  //= type=test
  //# The keyring MUST attempt to serialize the [decryption materials'](structures.md#decryption-materials)
  //# [encryption context](structures.md#encryption-context-1) according to the [encryption context serialization specification](structures.md#serialization).
  //= spec/framework/raw-aes-keyring.md#ondecrypt
  //= type=test
  //# If no decryption succeeds, the keyring MUST fail and MUST NOT modify
  //# the [decryption materials](structures.md#decryption-materials).
  //= spec/framework/raw-aes-keyring.md#ondecrypt
  //= type=test
  //# The keyring MUST perform the following actions on each encrypted data
  //# key](structures.md#encrypted-data-key) in the input encrypted data
  //# key list, serially, until it successfully decrypts one.
  void decryptFailures() {
    CreateRawAesKeyringInput keyringInput = input(NAMESPACE, NAME, 32, AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16);
    Pair keyrings = aes(keyringInput);
    Pair otherKey = aes(keyringInput.toBuilder().wrappingKey(ByteBuffer.wrap(bytes(32, 99))).build());
    for (AlgorithmSuiteId suite : allSuites()) {
      Map<String, String> encryptionContext = map("a", "b");
      EncryptionMaterials encrypted = keyrings.nativeEncrypt(encryptionMaterials(suite, encryptionContext, false));
      EncryptedDataKey good = encrypted.encryptedDataKeys().get(0);
      byte[] info = array(good.keyProviderInfo());
      byte[] ciphertext = array(good.ciphertext());
      DecryptionMaterials materials = decryptionMaterials(encrypted);
      int dataKeyLength = array(encrypted.plaintextDataKey()).length;

      List<List<EncryptedDataKey>> edkLists = new ArrayList<>();
      edkLists.add(Collections.emptyList());
      edkLists.add(Collections.singletonList(good));
      edkLists.add(Collections.singletonList(edk("other", info, ciphertext)));
      edkLists.add(Collections.singletonList(edk("namespacx", info, ciphertext)));
      edkLists.add(Collections.singletonList(edk(NAMESPACE, Arrays.copyOf(info, info.length - 1), ciphertext)));
      edkLists.add(Collections.singletonList(edk(NAMESPACE, Arrays.copyOf(info, info.length + 1), ciphertext)));
      edkLists.add(Collections.singletonList(edk(NAMESPACE, flip(info, 0), ciphertext)));
      edkLists.add(Collections.singletonList(edk(NAMESPACE, flip(info, NAME.length() + 3), ciphertext)));
      edkLists.add(Collections.singletonList(edk(NAMESPACE, flip(info, NAME.length() + 7), ciphertext)));
      // A different IV: the tag no longer verifies.
      edkLists.add(Collections.singletonList(edk(NAMESPACE, flip(info, info.length - 1), ciphertext)));
      edkLists.add(Collections.singletonList(edk(NAMESPACE, info, flip(ciphertext, 0))));
      edkLists.add(Collections.singletonList(edk(NAMESPACE, info, flip(ciphertext, ciphertext.length - 1))));
      for (int length : new int[] { 0, 15, 16, 17, dataKeyLength + 15, dataKeyLength + 16, dataKeyLength + 31, dataKeyLength + 32 }) {
        if (length <= ciphertext.length) {
          edkLists.add(Collections.singletonList(edk(NAMESPACE, info, Arrays.copyOf(ciphertext, length))));
        }
      }
      // A wrapped key of the wrong length, under this keyring's key, IV, and the materials' AAD.
      byte[] iv = Arrays.copyOfRange(info, info.length - 12, info.length);
      for (int wrongLength : new int[] { 0, dataKeyLength - 1, dataKeyLength + 1 }) {
        ByteBuffer wrapped = aesGcm(bytes(32, 1), iv, bytes(wrongLength, 5), aad(materials.encryptionContext()));
        edkLists.add(Collections.singletonList(edk(NAMESPACE, info, wrapped)));
      }
      // Failures before a success, and a success before a failure.
      edkLists.add(Arrays.asList(edk("other", info, ciphertext), edk(NAMESPACE, info, flip(ciphertext, 0)), good));
      edkLists.add(Arrays.asList(good, edk("other", info, ciphertext)));

      for (List<EncryptedDataKey> edks : edkLists) {
        keyrings.assertSameDecrypt(outcomes, materials, edks, ReferenceMpl.describe(suite));
        otherKey.assertSameDecrypt(outcomes, materials, edks, ReferenceMpl.describe(suite));
      }
      // The encryption context is the AAD.
      DecryptionMaterials otherContext = decryptionMaterials(encrypted, map("a", "c"));
      keyrings.assertSameDecrypt(outcomes, otherContext, Collections.singletonList(good), ReferenceMpl.describe(suite));
      // Materials that are not valid: a signing suite's verification key removed, a required context key missing.
      if (materials.verificationKey() != null) {
        keyrings.assertSameDecrypt(outcomes, materials.toBuilder().verificationKey(null).build(), Collections.singletonList(good), ReferenceMpl.describe(suite));
      }
      DecryptionMaterials missingRequired = materials.toBuilder().requiredEncryptionContextKeys(Collections.singletonList("missing")).build();
      keyrings.assertSameDecrypt(outcomes, missingRequired, Collections.singletonList(good), ReferenceMpl.describe(suite));
      // A context that cannot be serialized as AAD fails even with no keys to try.
      DecryptionMaterials unserializable = decryptionMaterials(encrypted, map(repeat('k', 65536), "v"));
      keyrings.assertSameDecrypt(outcomes, unserializable, Collections.emptyList(), ReferenceMpl.describe(suite));
      // Materials that already hold a data key.
      DecryptionMaterials decrypted = keyrings.nativeDecrypt(materials, Collections.singletonList(good));
      keyrings.assertSameDecrypt(outcomes, decrypted, Collections.singletonList(good), ReferenceMpl.describe(suite));
    }
    outcomes.assertBothSeen("OnDecrypt");
  }

  @Test
  void encryptFailures() {
    Pair keyrings = aes(input(NAMESPACE, NAME, 16, AesWrappingAlg.ALG_AES128_GCM_IV12_TAG16));
    for (AlgorithmSuiteId suite : allSuites()) {
      EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false);
      EncryptionMaterials withKey = encryptionMaterials(suite, map("a", "b"), true);
      int dataKeyLength = array(withKey.plaintextDataKey()).length;
      List<EncryptionMaterials> pool = new ArrayList<>();
      pool.add(start.toBuilder().plaintextDataKey(ByteBuffer.wrap(bytes(dataKeyLength + 1, 3))).build());
      pool.add(start.toBuilder().plaintextDataKey(ByteBuffer.wrap(bytes(dataKeyLength - 1, 3))).build());
      pool.add(start.toBuilder().encryptionContext(map()).build());
      pool.add(start.toBuilder().requiredEncryptionContextKeys(Collections.singletonList("missing")).build());
      pool.add(start.toBuilder().encryptedDataKeys(Collections.singletonList(edk("x", new byte[0], new byte[0]))).build());
      pool.add(start.toBuilder().signingKey(start.signingKey() == null ? ByteBuffer.wrap(bytes(48, 1)) : null).build());
      pool.add(withKey.toBuilder().encryptedDataKeys(Collections.singletonList(edk("x", new byte[0], new byte[0]))).build());
      pool.add(start.toBuilder().symmetricSigningKeys(Collections.singletonList(ByteBuffer.wrap(bytes(32, 1)))).build());
      //= spec/framework/raw-aes-keyring.md#onencrypt
      //= type=test
      //# The keyring MUST attempt to serialize the [encryption materials']
      //# (structures.md#encryption-materials) [encryption context]
      //# (structures.md#encryption-context-1) according to the
      //# [encryption context serialization specification](structures.md#serialization).
      //= spec/framework/raw-aes-keyring.md#onencrypt
      //= type=test
      //# If the keyring cannot serialize
      //# the encryption context, OnEncrypt MUST fail.
      pool.add(encryptionMaterials(suite, map(repeat('k', 65536), "v"), false));
      pool.add(encryptionMaterials(suite, map(repeat('k', 65536), "v"), true));
      pool.add(start);
      pool.add(withKey);
      for (EncryptionMaterials materials : pool) {
        keyrings.assertSameEncrypt(outcomes, materials, "");
      }
    }
    outcomes.assertBothSeen("OnEncrypt");
  }

  private static ByteBuffer iv(EncryptionMaterials materials) {
    byte[] info = array(materials.encryptedDataKeys().get(materials.encryptedDataKeys().size() - 1).keyProviderInfo());
    return ByteBuffer.wrap(Arrays.copyOfRange(info, info.length - 12, info.length));
  }

  private static String created(Object keyring) {
    return keyring == null ? "null" : "keyring";
  }

  private void assertSameOutcome(String operation, Supplier<Object> referenceCall, Supplier<Object> nativeCall) {
    String expected = ReferenceMpl.outcome(referenceCall);
    String actual = ReferenceMpl.outcome(nativeCall);
    assertEquals(expected, actual, operation);
    outcomes.record(operation, actual);
  }

  private static CreateRawAesKeyringInput input(String namespace, String name, int keyLength, AesWrappingAlg alg) {
    return CreateRawAesKeyringInput
      .builder()
      .keyNamespace(namespace)
      .keyName(name)
      .wrappingKey(ByteBuffer.wrap(bytes(keyLength, 1)))
      .wrappingAlg(alg)
      .build();
  }

  private static int keyLength(AesWrappingAlg alg) {
    switch (alg) {
      case ALG_AES128_GCM_IV12_TAG16:
        return 16;
      case ALG_AES192_GCM_IV12_TAG16:
        return 24;
      default:
        return 32;
    }
  }

  private static byte[] aad(Map<String, String> encryptionContext) {
    return CanonicalEncryptionContext.serialize(EncryptionContext.copyOf(encryptionContext));
  }

  private static ByteBuffer aesGcm(byte[] key, byte[] iv, byte[] plaintext, byte[] aad) {
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
      cipher.updateAAD(aad);
      return ByteBuffer.wrap(cipher.doFinal(plaintext));
    } catch (java.security.GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private Pair aes(CreateRawAesKeyringInput input) {
    return new Pair(MPL.CreateRawAesKeyring(input), ReferenceMpl.call(reference, "CreateRawAesKeyring", input));
  }
}
