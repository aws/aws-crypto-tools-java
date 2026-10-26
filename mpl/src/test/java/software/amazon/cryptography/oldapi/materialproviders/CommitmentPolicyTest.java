// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.oldapi.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.CommitmentPolicy;
import software.amazon.cryptography.oldapi.materialproviders.model.DBEAlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.DBECommitmentPolicy;
import software.amazon.cryptography.oldapi.materialproviders.model.ESDKAlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.ESDKCommitmentPolicy;
import software.amazon.cryptography.oldapi.materialproviders.model.MaterialProvidersConfig;
import software.amazon.cryptography.oldapi.materialproviders.model.ValidateCommitmentPolicyOnDecryptInput;
import software.amazon.cryptography.oldapi.materialproviders.model.ValidateCommitmentPolicyOnEncryptInput;

// Differential test against the published Dafny-based MPL over every suite, policy, and direction.
// The policy checks ignore the suite's format, so ESDK policies with DBE suites (and the reverse) are included.
class CommitmentPolicyTest {

  private final MaterialProviders mpl = MaterialProviders
    .builder()
    .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
    .build();
  private final Object reference = ReferenceMpl.materialProviders();

  //= spec/framework/commitment-policy.md#esdk-forbid-encrypt-allow-decrypt
  //= type=test
  //# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of False
  //
  //= spec/framework/commitment-policy.md#esdk-forbid-encrypt-allow-decrypt
  //= type=test
  //# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST support all algorithm suites
  //
  //= spec/framework/commitment-policy.md#esdk-require-encrypt-allow-decrypt
  //= type=test
  //# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True
  //
  //= spec/framework/commitment-policy.md#esdk-require-encrypt-allow-decrypt
  //= type=test
  //# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST support all algorithm suites
  //
  //= spec/framework/commitment-policy.md#esdk-require-encrypt-require-decrypt
  //= type=test
  //# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True
  //
  //= spec/framework/commitment-policy.md#esdk-require-encrypt-require-decrypt
  //= type=test
  //# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True
  //
  //= spec/framework/commitment-policy.md#dbe-require-encrypt-require-decrypt
  //= type=test
  //# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True
  //
  //= spec/framework/commitment-policy.md#dbe-require-encrypt-require-decrypt
  //= type=test
  //# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True
  @Test
  void matchesReferenceForEverySuitePolicyAndDirection() {
    TreeMap<String, Integer> outcomes = new TreeMap<>();
    for (AlgorithmSuiteId suite : allSuites()) {
      for (CommitmentPolicy policy : allPolicies()) {
        ValidateCommitmentPolicyOnEncryptInput encrypt = ValidateCommitmentPolicyOnEncryptInput
          .builder()
          .algorithm(suite)
          .commitmentPolicy(policy)
          .build();
        String encryptOutcome = ReferenceMpl.outcome(() -> {
          mpl.ValidateCommitmentPolicyOnEncrypt(encrypt);
          return null;
        });
        assertEquals(
          ReferenceMpl.outcome(() -> ReferenceMpl.call(reference, "ValidateCommitmentPolicyOnEncrypt", encrypt)),
          encryptOutcome,
          "encrypt " + ReferenceMpl.describe(encrypt)
        );
        outcomes.merge("encrypt " + encryptOutcome, 1, Integer::sum);

        ValidateCommitmentPolicyOnDecryptInput decrypt = ValidateCommitmentPolicyOnDecryptInput
          .builder()
          .algorithm(suite)
          .commitmentPolicy(policy)
          .build();
        String decryptOutcome = ReferenceMpl.outcome(() -> {
          mpl.ValidateCommitmentPolicyOnDecrypt(decrypt);
          return null;
        });
        assertEquals(
          ReferenceMpl.outcome(() -> ReferenceMpl.call(reference, "ValidateCommitmentPolicyOnDecrypt", decrypt)),
          decryptOutcome,
          "decrypt " + ReferenceMpl.describe(decrypt)
        );
        outcomes.merge("decrypt " + decryptOutcome, 1, Integer::sum);
      }
    }
    // 13 suites x 4 policies per direction. 4 of the 13 suites commit.
    // Encrypt: FORBID rejects the 4 committing suites; each of the 3 REQUIRE policies rejects the 9 others.
    // Decrypt: the 2 REQUIRE_ENCRYPT_REQUIRE_DECRYPT policies reject the 9 non-committing suites.
    TreeMap<String, Integer> expected = new TreeMap<>();
    String encryptError =
      "encrypt throws software.amazon.cryptography.materialproviders.model.InvalidAlgorithmSuiteInfoOnEncrypt: ";
    expected.put("encrypt void", 52 - 4 - 27);
    expected.put(encryptError + "Configuration conflict. Commitment policy requires only non-committing algorithm suites", 4);
    expected.put(encryptError + "Configuration conflict. Commitment policy requires only committing algorithm suites", 27);
    expected.put("decrypt void", 52 - 18);
    expected.put(
      "decrypt throws software.amazon.cryptography.materialproviders.model.InvalidAlgorithmSuiteInfoOnDecrypt: " +
      "Configuration conflict. Commitment policy requires only committing algorithm suites",
      18
    );
    assertEquals(expected, outcomes);
  }

  private static List<AlgorithmSuiteId> allSuites() {
    List<AlgorithmSuiteId> suites = new ArrayList<>();
    for (ESDKAlgorithmSuiteId id : ESDKAlgorithmSuiteId.values()) {
      suites.add(AlgorithmSuiteId.builder().ESDK(id).build());
    }
    for (DBEAlgorithmSuiteId id : DBEAlgorithmSuiteId.values()) {
      suites.add(AlgorithmSuiteId.builder().DBE(id).build());
    }
    return suites;
  }

  private static List<CommitmentPolicy> allPolicies() {
    List<CommitmentPolicy> policies = new ArrayList<>();
    for (ESDKCommitmentPolicy policy : ESDKCommitmentPolicy.values()) {
      policies.add(CommitmentPolicy.builder().ESDK(policy).build());
    }
    for (DBECommitmentPolicy policy : DBECommitmentPolicy.values()) {
      policies.add(CommitmentPolicy.builder().DBE(policy).build());
    }
    return policies;
  }
}
