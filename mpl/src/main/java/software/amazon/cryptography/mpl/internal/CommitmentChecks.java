// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal;

import software.amazon.cryptography.mpl.AlgorithmSuite;
import software.amazon.cryptography.mpl.CommitmentPolicy;
import software.amazon.cryptography.mpl.EsdkCommitmentPolicy;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

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
