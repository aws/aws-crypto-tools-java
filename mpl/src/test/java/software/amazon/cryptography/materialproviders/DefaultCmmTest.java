// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static software.amazon.cryptography.materialproviders.KeyringTests.*;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.materialproviders.KeyringTests.Outcomes;
import software.amazon.cryptography.materialproviders.KeyringTests.Pair;
import software.amazon.cryptography.materialproviders.model.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.AwsCryptographicMaterialProvidersException;
import software.amazon.cryptography.materialproviders.model.CommitmentPolicy;
import software.amazon.cryptography.materialproviders.model.CreateDefaultCryptographicMaterialsManagerInput;
import software.amazon.cryptography.materialproviders.model.CreateRawAesKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRequiredEncryptionContextCMMInput;
import software.amazon.cryptography.materialproviders.model.DBECommitmentPolicy;
import software.amazon.cryptography.materialproviders.model.DecryptMaterialsInput;
import software.amazon.cryptography.materialproviders.model.DecryptMaterialsOutput;
import software.amazon.cryptography.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.model.ESDKCommitmentPolicy;
import software.amazon.cryptography.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.model.GetEncryptionMaterialsInput;
import software.amazon.cryptography.materialproviders.model.GetEncryptionMaterialsOutput;
import software.amazon.cryptography.materialproviders.model.OnDecryptOutput;
import software.amazon.cryptography.materialproviders.model.OnEncryptOutput;
import software.amazon.cryptography.mpl.internal.primitives.Ecdsa;

// Differential tests of the default CMM against the published Dafny-based MPL.
// Signing key pairs and data keys are random: encryption results are compared with them masked,
// then each side decrypts the other's result.
class DefaultCmmTest {

  private static final String PUBLIC_KEY_FIELD = "aws-crypto-public-key";

  private final Object reference = ReferenceMpl.materialProviders();
  private final Outcomes outcomes = new Outcomes();
  private final Pair aes = aes();
  private final Map<String, Pair> keyrings = keyrings();

  //= spec/framework/default-cmm.md#get-encryption-materials
  //= type=test
  //# If the encryption context included in the [encryption materials request](cmm-interface.md#encryption-materials-request)
  //# already contains the `aws-crypto-public-key` key,
  //# this operation MUST fail rather than overwrite the associated value.
  //
  //= spec/framework/default-cmm.md#get-encryption-materials
  //= type=test
  //# If the algorithm suite contains a [signing algorithm](algorithm-suites.md#signature-algorithm),
  //# the default CMM MUST Add the key-value pair of
  //# key `aws-crypto-public-key`,
  //# value `base64-encoded public verification key`
  //# to the [encryption context](structures.md#encryption-context).
  //
  //= spec/framework/default-cmm.md#get-encryption-materials
  //= type=test
  //# If the algorithm suite contains a [signing algorithm](algorithm-suites.md#signature-algorithm),
  //# the default CMM MUST Generate a [signing key](structures.md#signing-key).
  //
  //= spec/framework/default-cmm.md#get-encryption-materials
  //= type=test
  //# - If the [encryption materials request](cmm-interface.md#encryption-
  //# materials-request) does contain an algorithm suite, the encryption
  //# materials returned MUST contain the same algorithm suite.
  //
  //= spec/framework/default-cmm.md#get-encryption-materials
  //= type=test
  //# - If the [encryption materials request](cmm-interface.md#encryption-
  //# materials-request) does not contain an algorithm suite, the
  //# operation MUST add the default algorithm suite for the [commitment
  //# policy](./commitment-policy.md#supported-commitment-policy-enum) as the
  //# algorithm suite in the encryption materials returned.
  //
  //= spec/framework/default-cmm.md#get-encryption-materials
  //= type=test
  //# - If the [encryption materials request](cmm-interface.md#encryption-
  //# materials-request) does contain an algorithm suite, the request
  //# MUST fail if the algorithm suite is not supported by the
  //# [commitment policy](./commitment-policy.md#supported-commitment-policy-enum) on
  //# the request.
  //
  //= spec/framework/default-cmm.md#get-encryption-materials
  //= type=test
  //# On each call to Get Encryption Materials,
  //# the default CMM MUST make a call to its [keyring's](#keyring)
  //# [On Encrypt](keyring-interface.md#onencrypt) operation.
  //
  //= spec/framework/commitment-policy.md#esdk-require-encrypt-allow-decrypt
  //= type=test
  //# - `05 78` MUST be the default algorithm suite
  //
  //= spec/framework/commitment-policy.md#esdk-require-encrypt-require-decrypt
  //= type=test
  //# - `05 78` MUST be the default algorithm suite
  //
  //= spec/framework/commitment-policy.md#dbe-require-encrypt-require-decrypt
  //= type=test
  //# - `67 01` MUST be the default algorithm suite
  //= spec/framework/cmm-interface.md#get-encryption-materials
  //= type=test
  //# The CMM MUST ensure that the encryption materials returned are valid.
  //# - The encryption materials returned MUST follow the specification for [encryption-materials](structures.md#encryption-materials).
  //# - The value of the plaintext data key MUST be non-NULL.
  //# - The plaintext data key length MUST be equal to the [key derivation input length](algorithm-suites.md#key-derivation-input-length).
  //# - The encrypted data keys list MUST contain at least one encrypted data key.
  //# - If the algorithm suite contains a signing algorithm, the encryption materials returned MUST include the generated signing key.
  //# - For every key in [Required Encryption Context Keys](structures.md#required-encryption-context-keys)
  //#   there MUST be a matching key in the [Encryption Context](structures.md#encryption-context-1).
  //
  //= spec/framework/cmm-interface.md#get-encryption-materials
  //= type=test
  //# If the algorithm suite contains a [signing algorithm](algorithm-suites.md#signature-algorithm):
  //#
  //# - The CMM MUST include a [signing key](structures.md#signing-key).
  //# - The CMM SHOULD also add a key-value pair using the reserved key `aws-crypto-public-key` to the encryption context.
  //#   If it does, the mapped value SHOULD be the signature verification key corresponding to the signing key.
  //#
  //# If the algorithm suite does not contain a [signing algorithm](algorithm-suites.md#signature-algorithm):
  //#
  //# - The CMM SHOULD NOT add a key-value pair using the reserved key `aws-crypto-public-key` to the encryption context.
  @Test
  void getEncryptionMaterials() {
    List<Map<String, String>> contexts = Arrays.asList(map(), map("a", "1"), map(PUBLIC_KEY_FIELD, "x"));
    for (Map.Entry<String, Pair> keyring : keyrings.entrySet()) {
      CmmPair cmm = cmm(keyring.getValue());
      for (CommitmentPolicy policy : policies()) {
        List<AlgorithmSuiteId> suites = new ArrayList<>(allSuites());
        suites.add(null);
        for (AlgorithmSuiteId suite : suites) {
          for (Map<String, String> context : contexts) {
            for (List<String> required : Arrays.asList(null, Collections.singletonList("a"))) {
              GetEncryptionMaterialsInput input = GetEncryptionMaterialsInput
                .builder()
                .encryptionContext(context)
                .commitmentPolicy(policy)
                .algorithmSuiteId(suite)
                .maxPlaintextLength(suite == null ? null : 100L)
                .requiredEncryptionContextKeys(required)
                .build();
              String label = keyring.getKey() + " " + ReferenceMpl.describe(input);
              String expected = ReferenceMpl.outcome(() -> masked(cmm.referenceEncrypt(input)));
              String actual = ReferenceMpl.outcome(() -> masked(cmm.nativeCmm.GetEncryptionMaterials(input).encryptionMaterials()));
              assertEquals(expected, actual, label);
              if (outcomes.record("GetEncryptionMaterials", actual).startsWith("throws")) {
                continue;
              }
              for (EncryptionMaterials result : Arrays.asList(cmm.nativeCmm.GetEncryptionMaterials(input).encryptionMaterials(), cmm.referenceEncrypt(input))) {
                assertSameDecrypt(cmm, decryptInput(result, policy, result.encryptionContext(), null), label);
                assertSigningKeyPairMatches(result, label);
              }
            }
          }
        }
      }
    }
    outcomes.assertBothSeen("GetEncryptionMaterials");
  }

  //= spec/framework/default-cmm.md#decrypt-materials
  //= type=test
  //# If this key is not present in the encryption context, the operation MUST fail
  //# without returning any decryption materials.
  //
  //= spec/framework/default-cmm.md#decrypt-materials
  //= type=test
  //# If the algorithm suite contains a [signing algorithm](algorithm-suites.md#signature-algorithm),
  //# the default CMM MUST extract the verification key
  //# from the encryption context under the reserved `aws-crypto-public-key` key.
  //
  //= spec/framework/default-cmm.md#decrypt-materials
  //= type=test
  //# The request MUST fail if the algorithm suite on the request is not
  //# supported by the [commitment policy](./commitment-policy.md#supported-commitment-policy-enum)
  //# on the request.
  //
  //= spec/framework/default-cmm.md#decrypt-materials
  //= type=test
  //# On each call to Decrypt Materials,
  //# the default CMM MUST make a call to its [keyring's](#keyring)
  //# [On Decrypt](keyring-interface.md#ondecrypt) operation.
  //= spec/framework/cmm-interface.md#decrypt-materials
  //= type=test
  //# The CMM MUST validate the [Encryption Context](structures.md#encryption-context)
  //# by comparing it to the customer supplied [Reproduced Encryption Context](structures.md#encryption-context)
  //# in [decrypt materials request](#decrypt-materials-request).
  //# For every key that exists in both [Reproduced Encryption Context](structures.md#encryption-context)
  //# and [Encryption Context](structures.md#encryption-context),
  //# the values MUST be equal or the operation MUST fail.
  //
  //= spec/framework/cmm-interface.md#decrypt-materials
  //= type=test
  //# - All key-value pairs that exist in [Reproduced Encryption Context](structures.md#encryption-context)
  //# but do not exist in encryption context on the [decrypt materials request](#decrypt-materials-request)
  //# SHOULD be appended to the decryption materials.
  //
  //= spec/framework/cmm-interface.md#decrypt-materials
  //= type=test
  //# - This set MUST include all keys added to the decryption materials encryption context
  //# that existed in the [decrypt materials request's](#decrypt-materials-request) reproduced encryption context
  //# but did not exist in the [decrypt materials request's](#decrypt-materials-request) encryption context.
  //
  //= spec/framework/cmm-interface.md#decrypt-materials
  //= type=test
  //# The CMM MUST ensure that the decryption materials returned are valid.
  //# - The decryption materials returned MUST follow the specification for [decryption-materials](structures.md#decryption-materials).
  //# - The value of the plaintext data key MUST be non-NULL.
  @Test
  void decryptMaterials() {
    CommitmentPolicy esdk = CommitmentPolicy.builder().ESDK(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT).build();
    for (AlgorithmSuiteId suite : allSuites()) {
      GetEncryptionMaterialsInput encryptInput = GetEncryptionMaterialsInput
        .builder()
        .encryptionContext(map("a", "1", "c", "2"))
        .commitmentPolicy(encryptPolicy(suite))
        .algorithmSuiteId(suite)
        .requiredEncryptionContextKeys(Collections.singletonList("c"))
        .build();
      EncryptionMaterials encrypted = cmm(aes).nativeCmm.GetEncryptionMaterials(encryptInput).encryptionMaterials();
      Map<String, String> stored = new HashMap<>(encrypted.encryptionContext());
      stored.remove("c");
      List<Map<String, String>> reproducedContexts = Arrays.asList(null, map(), map("c", "2"), map("c", "x"), map("a", "1", "c", "2"), map("a", "x", "c", "2"), map("d", "4", "c", "2", "b", "3"));
      for (Map.Entry<String, Pair> keyring : keyrings.entrySet()) {
        CmmPair cmm = cmm(keyring.getValue());
        for (CommitmentPolicy policy : Arrays.asList(policyFor(suite), esdk)) {
          for (Map<String, String> reproduced : reproducedContexts) {
            assertSameDecrypt(cmm, decryptInput(encrypted, policy, stored, reproduced), keyring.getKey());
          }
          Map<String, String> noPublicKey = new HashMap<>(stored);
          noPublicKey.remove(PUBLIC_KEY_FIELD);
          assertSameDecrypt(cmm, decryptInput(encrypted, policy, noPublicKey, map("c", "2")), keyring.getKey());
          Map<String, String> badPublicKey = new HashMap<>(stored);
          badPublicKey.put(PUBLIC_KEY_FIELD, "not base64!");
          assertSameDecrypt(cmm, decryptInput(encrypted, policy, badPublicKey, map("c", "2")), keyring.getKey());
        }
      }
    }
    outcomes.assertBothSeen("DecryptMaterials");
  }

  // The signing key signs what the verification key in the context verifies.
  private static void assertSigningKeyPairMatches(EncryptionMaterials materials, String label) {
    software.amazon.cryptography.mpl.AlgorithmSuite suite = software.amazon.cryptography.materialproviders.internal.Convert.suite(
      materials.algorithmSuite().id()
    );
    if (!suite.signature().isPresent()) {
      return;
    }
    // The signing key is the scalar as BigInteger.toByteArray() writes it: positive, no extra leading zero byte.
    byte[] signingKey = array(materials.signingKey());
    java.math.BigInteger scalar = new java.math.BigInteger(signingKey);
    assertEquals(1, scalar.signum(), label);
    assertEquals(ReferenceMpl.describe(ByteBuffer.wrap(scalar.toByteArray())), ReferenceMpl.describe(ByteBuffer.wrap(signingKey)), label);
    byte[] message = bytes(20, 7);
    byte[] signature = Ecdsa.sign(suite.signature().get(), array(materials.signingKey()), message);
    byte[] verificationKey = java.util.Base64.getDecoder().decode(materials.encryptionContext().get(PUBLIC_KEY_FIELD));
    assertEquals(true, Ecdsa.verify(suite.signature().get(), verificationKey, message, signature), label);
  }

  @Test
  void underRequiredEncryptionContextCmm() {
    CmmPair inner = cmm(aes);
    CreateRequiredEncryptionContextCMMInput.Builder input = CreateRequiredEncryptionContextCMMInput
      .builder()
      .requiredEncryptionContextKeys(Arrays.asList("c", "a"));
    // The reference input is built directly: the reference CMM cannot be wrapped as a native one.
    CmmPair required = new CmmPair(
      MPL.CreateRequiredEncryptionContextCMM(input.underlyingCMM(inner.nativeCmm).build()),
      ReferenceMpl.call(reference, "CreateRequiredEncryptionContextCMM", ReferenceMpl.build(
        "materialproviders.model.CreateRequiredEncryptionContextCMMInput",
        "underlyingCMM",
        inner.referenceCmm,
        "requiredEncryptionContextKeys",
        Arrays.asList("c", "a")
      ))
    );
    for (AlgorithmSuiteId suite : allSuites()) {
      CommitmentPolicy policy = encryptPolicy(suite);
      GetEncryptionMaterialsInput encrypt = GetEncryptionMaterialsInput
        .builder()
        .encryptionContext(map("a", "1", "b", "2", "c", "3"))
        .commitmentPolicy(policy)
        .algorithmSuiteId(suite)
        .requiredEncryptionContextKeys(Collections.singletonList("b"))
        .build();
      String expected = ReferenceMpl.outcome(() -> masked(required.referenceEncrypt(encrypt)));
      String actual = ReferenceMpl.outcome(() -> masked(required.nativeCmm.GetEncryptionMaterials(encrypt).encryptionMaterials()));
      assertEquals(expected, actual, ReferenceMpl.describe(encrypt));
      for (EncryptionMaterials result : Arrays.asList(required.nativeCmm.GetEncryptionMaterials(encrypt).encryptionMaterials(), required.referenceEncrypt(encrypt))) {
        Map<String, String> stored = new HashMap<>(result.encryptionContext());
        stored.remove("a");
        stored.remove("b");
        stored.remove("c");
        assertSameDecrypt(required, decryptInput(result, policy, stored, map("a", "1", "b", "2", "c", "3")), "required-EC over default");
        assertSameDecrypt(required, decryptInput(result, policy, stored, map("a", "1", "c", "3")), "required-EC over default");
      }
    }
  }

  private void assertSameDecrypt(CmmPair cmm, DecryptMaterialsInput input, String label) {
    String expected = ReferenceMpl.outcome(
      () -> sortedKeys(((DecryptMaterialsOutput) ReferenceMpl.fromReference(ReferenceMpl.call(cmm.referenceCmm, "DecryptMaterials", input))).decryptionMaterials())
    );
    String actual = ReferenceMpl.outcome(() -> sortedKeys(cmm.nativeCmm.DecryptMaterials(input).decryptionMaterials()));
    assertEquals(expected, actual, label + " " + ReferenceMpl.describe(input));
    outcomes.record("DecryptMaterials", actual);
  }

  private static DecryptMaterialsInput decryptInput(
    EncryptionMaterials encrypted,
    CommitmentPolicy policy,
    Map<String, String> stored,
    Map<String, String> reproduced
  ) {
    return DecryptMaterialsInput
      .builder()
      .algorithmSuiteId(encrypted.algorithmSuite().id())
      .commitmentPolicy(policy)
      .encryptedDataKeys(encrypted.encryptedDataKeys())
      .encryptionContext(stored)
      .reproducedEncryptionContext(reproduced)
      .build();
  }

  private static final class CmmPair {

    final ICryptographicMaterialsManager nativeCmm;
    final Object referenceCmm;

    CmmPair(ICryptographicMaterialsManager nativeCmm, Object referenceCmm) {
      this.nativeCmm = nativeCmm;
      this.referenceCmm = referenceCmm;
    }

    EncryptionMaterials referenceEncrypt(GetEncryptionMaterialsInput input) {
      return ((GetEncryptionMaterialsOutput) ReferenceMpl.fromReference(ReferenceMpl.call(referenceCmm, "GetEncryptionMaterials", input))).encryptionMaterials();
    }
  }

  private CmmPair cmm(Pair keyring) {
    CreateDefaultCryptographicMaterialsManagerInput input = CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(keyring).build();
    CreateDefaultCryptographicMaterialsManagerInput nativeInput = CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(keyring.nativeKeyring).build();
    return new CmmPair(MPL.CreateDefaultCryptographicMaterialsManager(nativeInput), ReferenceMpl.call(reference, "CreateDefaultCryptographicMaterialsManager", input));
  }

  // The built-in AES keyring, and caller keyrings around it that are wrong in some way.
  private Map<String, Pair> keyrings() {
    Map<String, Pair> pairs = new LinkedHashMap<>();
    pairs.put("aes", aes);
    pairs.put(
      "throws",
      Pair.custom(
        input -> {
          throw AwsCryptographicMaterialProvidersException.builder().message("custom failure").build();
        },
        input -> {
          throw AwsCryptographicMaterialProvidersException.builder().message("custom failure").build();
        }
      )
    );
    pairs.put(
      "returns its input",
      Pair.custom(
        input -> OnEncryptOutput.builder().materials(input.materials()).build(),
        input -> OnDecryptOutput.builder().materials(input.materials()).build()
      )
    );
    pairs.put(
      "changes the context",
      Pair.custom(
        input -> {
          EncryptionMaterials m = aes.OnEncrypt(input).materials();
          Map<String, String> context = new HashMap<>(m.encryptionContext());
          context.put("x", "y");
          return OnEncryptOutput.builder().materials(m.toBuilder().encryptionContext(context).build()).build();
        },
        input -> {
          DecryptionMaterials m = aes.OnDecrypt(input).materials();
          Map<String, String> context = new HashMap<>(m.encryptionContext());
          context.put("x", "y");
          return OnDecryptOutput.builder().materials(m.toBuilder().encryptionContext(context).build()).build();
        }
      )
    );
    return pairs;
  }

  private Pair aes() {
    CreateRawAesKeyringInput input = CreateRawAesKeyringInput
      .builder()
      .keyNamespace("ns")
      .keyName("name")
      .wrappingKey(ByteBuffer.wrap(bytes(32, 1)))
      .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
      .build();
    return new Pair(MPL.CreateRawAesKeyring(input), ReferenceMpl.call(reference, "CreateRawAesKeyring", input));
  }

  private static List<CommitmentPolicy> policies() {
    List<CommitmentPolicy> policies = new ArrayList<>();
    for (ESDKCommitmentPolicy policy : ESDKCommitmentPolicy.values()) {
      policies.add(CommitmentPolicy.builder().ESDK(policy).build());
    }
    for (DBECommitmentPolicy policy : DBECommitmentPolicy.values()) {
      policies.add(CommitmentPolicy.builder().DBE(policy).build());
    }
    return policies;
  }

  private static CommitmentPolicy policyFor(AlgorithmSuiteId suite) {
    return suite.DBE() != null
      ? CommitmentPolicy.builder().DBE(DBECommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT).build()
      : CommitmentPolicy.builder().ESDK(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT).build();
  }

  // A policy that allows encrypting with {@code suite}.
  private static CommitmentPolicy encryptPolicy(AlgorithmSuiteId suite) {
    if (suite.DBE() != null || software.amazon.cryptography.materialproviders.internal.Convert.suite(suite).isCommitting()) {
      return policyFor(suite);
    }
    return CommitmentPolicy.builder().ESDK(ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT).build();
  }

  // Masks the random signing key and the verification key in the context, on top of the keyring masking.
  private static String masked(EncryptionMaterials materials) {
    Map<String, String> context = new HashMap<>(materials.encryptionContext());
    String publicKey = context.get(PUBLIC_KEY_FIELD);
    if (publicKey != null) {
      context.put(PUBLIC_KEY_FIELD, "base64 of length " + publicKey.length());
    }
    List<String> required = new ArrayList<>(materials.requiredEncryptionContextKeys());
    Collections.sort(required);
    EncryptionMaterials rest = materials
      .toBuilder()
      .encryptionContext(context)
      .requiredEncryptionContextKeys(required)
      // The signing scalar's two's-complement encoding varies in length with the random key.
      .signingKey(materials.signingKey() == null ? null : ByteBuffer.wrap(new byte[1]))
      .build();
    return KeyringTests.masked(rest, false);
  }

  private static String sortedKeys(DecryptionMaterials materials) {
    List<String> keys = new ArrayList<>(materials.requiredEncryptionContextKeys());
    Collections.sort(keys);
    return ReferenceMpl.describe(materials.toBuilder().requiredEncryptionContextKeys(keys).build());
  }
}
