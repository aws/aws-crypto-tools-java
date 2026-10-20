// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.cache;

import software.amazon.cryptography.mpl.exceptions.ValidationException;

/** Input to {@link CryptographicMaterialsCache#getCacheEntry}. Immutable. */
public final class GetCacheEntryRequest {

  private final CacheKey key;

  private GetCacheEntryRequest(Builder builder) {
    this.key = builder.key;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** The same as {@code builder().key(key).build()}. */
  public static GetCacheEntryRequest of(CacheKey key) {
    return builder().key(key).build();
  }

  /** A builder holding this request's values. */
  public Builder toBuilder() {
    return new Builder().key(key);
  }

  public CacheKey key() {
    return key;
  }

  @Override
  public String toString() {
    return "GetCacheEntryRequest[" + key + "]";
  }

  /** Not thread-safe. Requires a key. */
  public static final class Builder {

    private CacheKey key;

    private Builder() {}

    public Builder key(CacheKey key) {
      this.key = key;
      return this;
    }

    public GetCacheEntryRequest build() {
      if (key == null) {
        throw new ValidationException("Missing value for required field `key`");
      }
      return new GetCacheEntryRequest(this);
    }
  }
}
