// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.cache;

import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.internal.cache.BuiltInCache;
import software.amazon.cryptography.materialproviders.internal.cache.CacheClock;
import software.amazon.cryptography.materialproviders.internal.cache.Caches;

/**
 * A storm-tracking cache with the default tuning: a 10-second grace period, 1-second grace interval, fan-out 20,
 * 10-second in-flight TTL, and 20-millisecond sleep, the same as {@link StormTrackingCache.Builder}'s defaults.
 * A hierarchical keyring with no cache set builds one of these with 1000 entries. Thread-safe.
 *
 * <p>A keyring given this cache does not check its TTL against the grace period, as it does for a {@link StormTrackingCache};
 * see {@link software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring.Builder#cache}.
 */
public final class DefaultCache implements CryptographicMaterialsCache {

  private final int entryCapacity;
  private final BuiltInCache cache;

  private DefaultCache(int entryCapacity) {
    this.entryCapacity = entryCapacity;
    this.cache = new BuiltInCache(Caches.stormTracking(Caches.defaultSettings(entryCapacity), CacheClock.SYSTEM));
  }

  public static Builder builder() {
    return new Builder();
  }

  public int entryCapacity() {
    return entryCapacity;
  }

  @Override
  public GetCacheEntryResponse getCacheEntry(GetCacheEntryRequest request) {
    return cache.getCacheEntry(request);
  }

  @Override
  public PutCacheEntryResponse putCacheEntry(PutCacheEntryRequest request) {
    return cache.putCacheEntry(request);
  }

  @Override
  public DeleteCacheEntryResponse deleteCacheEntry(DeleteCacheEntryRequest request) {
    return cache.deleteCacheEntry(request);
  }

  @Override
  public String toString() {
    return "DefaultCache[entryCapacity=" + entryCapacity + "]";
  }

  /** Not thread-safe. Requires {@code entryCapacity}. */
  public static final class Builder {

    private Integer entryCapacity;

    private Builder() {}

    /** At least 1. */
    public Builder entryCapacity(int entryCapacity) {
      this.entryCapacity = entryCapacity;
      return this;
    }

    /** @throws ValidationException if {@code entryCapacity} is missing or below 1 */
    public DefaultCache build() {
      if (entryCapacity == null) {
        throw new ValidationException("Missing value for required field `entryCapacity`");
      }
      return new DefaultCache(entryCapacity);
    }
  }
}
