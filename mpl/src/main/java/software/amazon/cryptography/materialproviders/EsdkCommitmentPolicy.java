// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

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
    //= spec/framework/commitment-policy.md#esdk-forbid-encrypt-allow-decrypt
    //# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of False
    //
    //= spec/framework/commitment-policy.md#esdk-require-encrypt-allow-decrypt
    //# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True
    //
    //= spec/framework/commitment-policy.md#esdk-require-encrypt-require-decrypt
    //# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True
    return this == FORBID_ENCRYPT_ALLOW_DECRYPT ? !suite.isCommitting() : suite.isCommitting();
  }

  @Override
  public boolean allowsDecrypt(AlgorithmSuite suite) {
    //= spec/framework/commitment-policy.md#esdk-forbid-encrypt-allow-decrypt
    //= type=implication
    //# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST support all algorithm suites
    //
    //= spec/framework/commitment-policy.md#esdk-require-encrypt-allow-decrypt
    //= type=implication
    //# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST support all algorithm suites
    //
    //= spec/framework/commitment-policy.md#esdk-require-encrypt-require-decrypt
    //# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True
    return this != REQUIRE_ENCRYPT_REQUIRE_DECRYPT || suite.isCommitting();
  }

  // Per Defaults.dfy, which returns 0x0378 for FORBID although the spec text it cites names 0x0078.
  @Override
  public AlgorithmSuite defaultSuite() {
    return this == FORBID_ENCRYPT_ALLOW_DECRYPT
      //= spec/framework/commitment-policy.md#esdk-forbid-encrypt-allow-decrypt
      //= type=exception
      //= reason=The default suite for FORBID_ENCRYPT_ALLOW_DECRYPT is 0x0378 (HKDF-SHA384 with ECDSA P-384), as in the Dafny MPL.
      //# - `ESDK.ALG_AES_256_GCM_IV12_TAG16_NO_KDF` MUST be the default algorithm suite
      ? AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
      //= spec/framework/commitment-policy.md#esdk-require-encrypt-allow-decrypt
      //# - `05 78` MUST be the default algorithm suite
      //
      //= spec/framework/commitment-policy.md#esdk-require-encrypt-require-decrypt
      //# - `05 78` MUST be the default algorithm suite
      : AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384;
  }
}
