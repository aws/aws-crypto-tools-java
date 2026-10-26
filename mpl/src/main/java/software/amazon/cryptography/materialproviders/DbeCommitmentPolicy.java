// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

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
    //= spec/framework/commitment-policy.md#dbe-require-encrypt-require-decrypt
    //# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True
    return suite.isCommitting();
  }

  @Override
  public boolean allowsDecrypt(AlgorithmSuite suite) {
    //= spec/framework/commitment-policy.md#dbe-require-encrypt-require-decrypt
    //# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True
    return suite.isCommitting();
  }

  @Override
  public AlgorithmSuite defaultSuite() {
    //= spec/framework/commitment-policy.md#dbe-require-encrypt-require-decrypt
    //# - `67 01` MUST be the default algorithm suite
    return AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384;
  }
}
