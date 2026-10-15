// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal.primitives;

/** SHA-2 digests the library uses, for HMAC, HKDF, and KDF in counter mode. */
public enum DigestAlgorithm {
  SHA_256,
  SHA_384,
  SHA_512,
}
