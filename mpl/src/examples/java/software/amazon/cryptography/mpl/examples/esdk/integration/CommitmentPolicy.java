// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples.esdk.integration;

import software.amazon.cryptography.mpl.EsdkCommitmentPolicy;

/**
 * The ESDK's {@code com.amazonaws.encryptionsdk.CommitmentPolicy}, mapped onto the native {@link EsdkCommitmentPolicy}.
 * ESDK 3.x built the MPL's {@code CommitmentPolicy} union per constant and kept its own copy of the rules;
 * here the rules come from the MPL policy.
 */
public enum CommitmentPolicy {
  ForbidEncryptAllowDecrypt(EsdkCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT),
  RequireEncryptAllowDecrypt(EsdkCommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT),
  RequireEncryptRequireDecrypt(EsdkCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);

  private final EsdkCommitmentPolicy mplCommitmentPolicy;

  CommitmentPolicy(EsdkCommitmentPolicy mplCommitmentPolicy) {
    this.mplCommitmentPolicy = mplCommitmentPolicy;
  }

  /** Same name as in ESDK 3.x; the type is now the native enum. */
  public EsdkCommitmentPolicy getMplCommitmentPolicy() {
    return mplCommitmentPolicy;
  }

  public boolean algorithmAllowedForEncrypt(CryptoAlgorithm algorithm) {
    return mplCommitmentPolicy.allowsEncrypt(algorithm.algorithmSuite());
  }

  public boolean algorithmAllowedForDecrypt(CryptoAlgorithm algorithm) {
    return mplCommitmentPolicy.allowsDecrypt(algorithm.algorithmSuite());
  }
}
