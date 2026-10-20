// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.cache;

/** Output of {@link CryptographicMaterialsCache#putCacheEntry}; it has no members yet. Immutable. */
public final class PutCacheEntryResponse {

  private PutCacheEntryResponse(Builder builder) {}

  public static Builder builder() {
    return new Builder();
  }

  /** The same as {@code builder().build()}. */
  public static PutCacheEntryResponse of() {
    return builder().build();
  }

  /** A builder holding this response's values. */
  public Builder toBuilder() {
    return new Builder();
  }

  @Override
  public String toString() {
    return "PutCacheEntryResponse[]";
  }

  /** Not thread-safe. */
  public static final class Builder {

    private Builder() {}

    public PutCacheEntryResponse build() {
      return new PutCacheEntryResponse(this);
    }
  }
}
