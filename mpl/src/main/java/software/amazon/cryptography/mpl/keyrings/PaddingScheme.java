// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

/** RSA encryption padding for {@link RawRsaKeyring}. More constants may be added; a {@code switch} needs a {@code default} branch. */
public enum PaddingScheme {
  PKCS1,
  OAEP_SHA1_MGF1,
  OAEP_SHA256_MGF1,
  OAEP_SHA384_MGF1,
  OAEP_SHA512_MGF1,
}
