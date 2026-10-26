// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keyrings;

/** Elliptic curves for the ECDH keyrings. More constants may be added; a {@code switch} needs a {@code default} branch. */
public enum EcdhCurveSpec {
  ECC_NIST_P256,
  ECC_NIST_P384,
  ECC_NIST_P521,
  /**
   * Not supported by any keyring yet: building a {@link RawEcdhKeyring} or {@link AwsKmsEcdhKeyring} with it
   * throws {@link software.amazon.cryptography.materialproviders.exceptions.ValidationException}.
   */
  SM2,
}
