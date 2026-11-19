// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.cache;

import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.internal.cache.BuiltInCache;
import software.amazon.cryptography.materialproviders.internal.cache.CacheClock;
import software.amazon.cryptography.materialproviders.internal.cache.Caches;

/** An LRU cache for use from one thread at a time: not thread-safe. */
public final class SingleThreadedCache implements CryptographicMaterialsCache {

  private final int entryCapacity;
  private final int entryPruningTailSize;
  private final BuiltInCache cache;

  private SingleThreadedCache(int entryCapacity, int entryPruningTailSize) {
    this.entryCapacity = entryCapacity;
    this.entryPruningTailSize = entryPruningTailSize;
    this.cache = new BuiltInCache(Caches.singleThreaded(entryCapacity, entryPruningTailSize, CacheClock.SYSTEM));
  }

  public static Builder builder() {
    return new Builder();
  }

  public int entryCapacity() {
    return entryCapacity;
  }

  public int entryPruningTailSize() {
    return entryPruningTailSize;
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
    return "SingleThreadedCache[entryCapacity=" + entryCapacity + ", entryPruningTailSize=" + entryPruningTailSize + "]";
  }

  /** Not thread-safe. Requires {@code entryCapacity}; {@code entryPruningTailSize} defaults to {@link StormTrackingCache#DEFAULT_ENTRY_PRUNING_TAIL_SIZE}. */
  //= spec/framework/local-cryptographic-materials-cache.md#initialization
  //= type=implication
  //# On initialization of the local CMC,
  //# the caller MUST provide the following:
  //#
  //# - [Entry Capacity](#entry-capacity)
  //#
  //# The local CMC MUST also define the following:
  //#
  //# - [Entry Pruning Tail Size](#entry-pruning-tail-size)
  public static final class Builder {

    private Integer entryCapacity;
    private int entryPruningTailSize = StormTrackingCache.DEFAULT_ENTRY_PRUNING_TAIL_SIZE;

    private Builder() {}

    /** At least 1. */
    public Builder entryCapacity(int entryCapacity) {
      this.entryCapacity = entryCapacity;
      return this;
    }

    /** Expired entries removed per prune pass; at least 1. */
    public Builder entryPruningTailSize(int entryPruningTailSize) {
      this.entryPruningTailSize = entryPruningTailSize;
      return this;
    }

    /** @throws ValidationException if {@code entryCapacity} is missing, or either number is below 1 */
    public SingleThreadedCache build() {
      Caches.checkLocal(entryCapacity, entryPruningTailSize);
      return new SingleThreadedCache(entryCapacity, entryPruningTailSize);
    }
  }
}
