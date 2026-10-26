// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.cache;

import java.util.Arrays;

/** Identifies a cache entry. Immutable; {@code equals} compares the bytes. */
public final class CacheKey {

  private final byte[] identifier;

  private CacheKey(byte[] identifier) {
    this.identifier = identifier;
  }

  public static CacheKey of(byte[] identifier) {
    return new CacheKey(identifier.clone());
  }

  /** A copy. */
  public byte[] identifier() {
    return identifier.clone();
  }

  @Override
  public boolean equals(Object other) {
    return other instanceof CacheKey && Arrays.equals(identifier, ((CacheKey) other).identifier);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(identifier);
  }

  /** The identifier in hex. */
  @Override
  public String toString() {
    StringBuilder hex = new StringBuilder(identifier.length * 2);
    for (byte b : identifier) {
      hex.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
    }
    return hex.toString();
  }
}
