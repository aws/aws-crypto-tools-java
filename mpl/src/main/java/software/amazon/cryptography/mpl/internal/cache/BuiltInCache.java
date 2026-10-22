// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal.cache;

import software.amazon.cryptography.mpl.cache.CacheEntry;
import software.amazon.cryptography.mpl.cache.CryptographicMaterialsCache;
import software.amazon.cryptography.mpl.cache.DeleteCacheEntryRequest;
import software.amazon.cryptography.mpl.cache.DeleteCacheEntryResponse;
import software.amazon.cryptography.mpl.cache.GetCacheEntryRequest;
import software.amazon.cryptography.mpl.cache.GetCacheEntryResponse;
import software.amazon.cryptography.mpl.cache.PutCacheEntryRequest;
import software.amazon.cryptography.mpl.cache.PutCacheEntryResponse;

/** The public cache interface over a built-in cache. */
public final class BuiltInCache implements CryptographicMaterialsCache {

  private final CacheEngine<CacheEntry> engine;

  public BuiltInCache(CacheEngine<CacheEntry> engine) {
    this.engine = engine;
  }

  @Override
  public GetCacheEntryResponse getCacheEntry(GetCacheEntryRequest request) {
    return GetCacheEntryResponse.builder().entry(engine.get(request.key()).value()).build();
  }

  @Override
  public PutCacheEntryResponse putCacheEntry(PutCacheEntryRequest request) {
    CacheEntry entry = request.entry();
    engine.put(request.key(), entry, entry.expiryTime().getEpochSecond());
    return PutCacheEntryResponse.builder().build();
  }

  @Override
  public DeleteCacheEntryResponse deleteCacheEntry(DeleteCacheEntryRequest request) {
    engine.remove(request.key());
    return DeleteCacheEntryResponse.builder().build();
  }
}
