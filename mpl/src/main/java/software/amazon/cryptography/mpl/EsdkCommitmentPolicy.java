// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl;

//= spec/framework/commitment-policy.md#supported-format-commitment-policy-enum
//= type=implication
//# The Material Providers Library MUST provide
//# a distinct commitment policy ENUM for each format.
//
//= spec/framework/commitment-policy.md#supported-format-commitment-policy-enum
//= type=implication
//# | ESDK Commitment Policy ENUM     |
//# | ------------------------------- |
//# | FORBID_ENCRYPT_ALLOW_DECRYPT    |
//# | REQUIRE_ENCRYPT_ALLOW_DECRYPT   |
//# | REQUIRE_ENCRYPT_REQUIRE_DECRYPT |
/** Commitment policies of the AWS Encryption SDK. More constants may be added; a {@code switch} needs a {@code default} branch. */
public enum EsdkCommitmentPolicy implements CommitmentPolicy {
  /** Encrypt only with non-committing suites; decrypt any suite. Default suite: 0x0378. */
  FORBID_ENCRYPT_ALLOW_DECRYPT,
  /** Encrypt only with committing suites; decrypt any suite. Default suite: 0x0578. */
  REQUIRE_ENCRYPT_ALLOW_DECRYPT,
  /** Encrypt and decrypt only with committing suites. Default suite: 0x0578. */
  REQUIRE_ENCRYPT_REQUIRE_DECRYPT;

  @Override
  public boolean allowsEncrypt(AlgorithmSuite suite) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  @Override
  public boolean allowsDecrypt(AlgorithmSuite suite) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  @Override
  public AlgorithmSuite defaultSuite() {
    throw new UnsupportedOperationException("not implemented yet");
  }
}
