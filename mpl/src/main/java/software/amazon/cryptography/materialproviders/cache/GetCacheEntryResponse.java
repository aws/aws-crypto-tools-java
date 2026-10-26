// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.cache;

import java.util.Optional;

/** Output of {@link CryptographicMaterialsCache#getCacheEntry}. Immutable. */
public final class GetCacheEntryResponse {

  private final CacheEntry entry;

  private GetCacheEntryResponse(Builder builder) {
    this.entry = builder.entry;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this response's values. */
  public Builder toBuilder() {
    return new Builder().entry(entry);
  }

  /** The entry; absent on a miss. */
  public Optional<CacheEntry> entry() {
    return Optional.ofNullable(entry);
  }

  @Override
  public String toString() {
    return "GetCacheEntryResponse[" + (entry == null ? "miss" : entry) + "]";
  }

  /** Not thread-safe. Without an entry the response is a miss. */
  public static final class Builder {

    private CacheEntry entry;

    private Builder() {}

    /** Null for a miss. */
    public Builder entry(CacheEntry entry) {
      this.entry = entry;
      return this;
    }

    public GetCacheEntryResponse build() {
      return new GetCacheEntryResponse(this);
    }
  }
}
