// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl;

//= spec/framework/commitment-policy.md#supported-format-commitment-policy-enum
//= type=implication
//# The Material Providers Library MUST provide
//# a distinct commitment policy ENUM for each format.
/** Commitment policies of the AWS Database Encryption SDK. More constants may be added; a {@code switch} needs a {@code default} branch. */
public enum DbeCommitmentPolicy implements CommitmentPolicy {
  /** Encrypt and decrypt only with committing suites. Default suite: 0x6701. */
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
