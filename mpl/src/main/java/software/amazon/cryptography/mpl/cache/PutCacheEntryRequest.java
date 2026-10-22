// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.cache;

import software.amazon.cryptography.mpl.exceptions.ValidationException;

/** Input to {@link CryptographicMaterialsCache#putCacheEntry}. Immutable. */
public final class PutCacheEntryRequest {

  private final CacheKey key;
  private final CacheEntry entry;

  private PutCacheEntryRequest(Builder builder) {
    this.key = builder.key;
    this.entry = builder.entry;
  }

  public static Builder builder() {
    return new Builder();
  }


  /** A builder holding this request's values. */
  public Builder toBuilder() {
    return new Builder().key(key).entry(entry);
  }

  public CacheKey key() {
    return key;
  }

  public CacheEntry entry() {
    return entry;
  }

  @Override
  public String toString() {
    return "PutCacheEntryRequest[" + key + ", " + entry + "]";
  }

  /** Not thread-safe. Requires a key and an entry. */
  public static final class Builder {

    private CacheKey key;
    private CacheEntry entry;

    private Builder() {}

    public Builder key(CacheKey key) {
      this.key = key;
      return this;
    }

    public Builder entry(CacheEntry entry) {
      this.entry = entry;
      return this;
    }

    public PutCacheEntryRequest build() {
      if (key == null) {
        throw new ValidationException("Missing value for required field `key`");
      }
      if (entry == null) {
        throw new ValidationException("Missing value for required field `entry`");
      }
      return new PutCacheEntryRequest(this);
    }
  }
}
