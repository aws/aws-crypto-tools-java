// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

//= spec/framework/commitment-policy.md#supported-commitment-policy-enum
//= type=implication
//# The Material Providers Library also MUST provide
//# a union ENUM for all distinct commitment policy ENUMs
//# called the Commitment Policy ENUM.
//
//= spec/framework/commitment-policy.md#supported-commitment-policy-enum
//= type=implication
//# This means that different formats MAY have duplicate Format Commitment Policy ENUM.
/**
 * Which algorithm suites may encrypt and decrypt, depending on whether they commit to their key.
 * The two implementations are {@link EsdkCommitmentPolicy} and {@link DbeCommitmentPolicy}; there are no others.
 * Not for implementation by callers: the built-in managers handle only those two, and another one passed to them
 * gets checks and error messages no other AWS Encryption SDK implementation has.
 *
 * <p>The checks look only at {@link AlgorithmSuite#isCommitting()}, not at the suite's format,
 * so an ESDK policy accepts DBE suites on the same terms.
 * {@link #defaultSuite()} returns the policy's own format: {@link EsdkCommitmentPolicy#defaultSuite()} an
 * {@link EsdkAlgorithmSuite}, {@link DbeCommitmentPolicy#defaultSuite()} a {@link DbeAlgorithmSuite}.
 */
public interface CommitmentPolicy {
  boolean allowsEncrypt(AlgorithmSuite suite);

  boolean allowsDecrypt(AlgorithmSuite suite);

  /** The suite a materials manager uses when the caller names none. */
  AlgorithmSuite defaultSuite();
}
