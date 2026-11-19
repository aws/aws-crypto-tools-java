// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.cache;

import software.amazon.cryptography.materialproviders.internal.cache.BuiltInCache;
import software.amazon.cryptography.materialproviders.internal.cache.CacheClock;
import software.amazon.cryptography.materialproviders.internal.cache.Caches;

/** Caches nothing: a hierarchical keyring given this cache reads the key store for every operation. Thread-safe. */
public final class NoCache implements CryptographicMaterialsCache {

  private final BuiltInCache cache = new BuiltInCache(Caches.noCache(CacheClock.SYSTEM));

  private NoCache() {}

  public static NoCache create() {
    return new NoCache();
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
    return "NoCache";
  }
}
