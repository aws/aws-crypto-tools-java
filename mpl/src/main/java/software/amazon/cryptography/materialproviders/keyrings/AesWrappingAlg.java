// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keyrings;

/** AES-GCM wrapping for {@link RawAesKeyring}: 12-byte IV, 16-byte tag. More constants may be added; a {@code switch} needs a {@code default} branch. */
public enum AesWrappingAlg {
  ALG_AES128_GCM_IV12_TAG16,
  ALG_AES192_GCM_IV12_TAG16,
  ALG_AES256_GCM_IV12_TAG16,
}
