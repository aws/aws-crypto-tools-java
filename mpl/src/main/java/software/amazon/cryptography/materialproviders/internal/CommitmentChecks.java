// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal;

import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.CommitmentPolicy;
import software.amazon.cryptography.materialproviders.EsdkCommitmentPolicy;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

/** The commitment policy checks of Commitment.dfy, with its messages, for the materials managers. */
public final class CommitmentChecks {

  private CommitmentChecks() {}

  public static void requireEncrypt(CommitmentPolicy policy, AlgorithmSuite suite) {
    if (!policy.allowsEncrypt(suite)) {
      throw new ValidationException(
        policy == EsdkCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
          ? "Configuration conflict. Commitment policy requires only non-committing algorithm suites"
          : "Configuration conflict. Commitment policy requires only committing algorithm suites"
      );
    }
  }

  public static void requireDecrypt(CommitmentPolicy policy, AlgorithmSuite suite) {
    if (!policy.allowsDecrypt(suite)) {
      throw new ValidationException("Configuration conflict. Commitment policy requires only committing algorithm suites");
    }
  }
}
