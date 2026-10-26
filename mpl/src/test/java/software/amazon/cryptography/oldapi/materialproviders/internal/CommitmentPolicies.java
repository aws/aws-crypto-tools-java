// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders.internal;

import software.amazon.cryptography.oldapi.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.CommitmentPolicy;
import software.amazon.cryptography.oldapi.materialproviders.model.InvalidAlgorithmSuiteInfoOnDecrypt;
import software.amazon.cryptography.oldapi.materialproviders.model.InvalidAlgorithmSuiteInfoOnEncrypt;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.CommitmentChecks;

/** Test adapter: the old commitment policy operations, implemented on the native core. */
public final class CommitmentPolicies {

  private CommitmentPolicies() {}

  public static void validateOnEncrypt(AlgorithmSuiteId algorithm, CommitmentPolicy policy) {
    try {
      CommitmentChecks.requireEncrypt(Convert.policy(policy), Convert.suite(algorithm));
    } catch (ValidationException e) {
      throw InvalidAlgorithmSuiteInfoOnEncrypt.builder().message(e.getMessage()).build();
    }
  }

  public static void validateOnDecrypt(AlgorithmSuiteId algorithm, CommitmentPolicy policy) {
    try {
      CommitmentChecks.requireDecrypt(Convert.policy(policy), Convert.suite(algorithm));
    } catch (ValidationException e) {
      throw InvalidAlgorithmSuiteInfoOnDecrypt.builder().message(e.getMessage()).build();
    }
  }
}
