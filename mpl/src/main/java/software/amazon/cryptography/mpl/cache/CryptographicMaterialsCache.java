// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.cache;

import java.util.Optional;

/**
 * Caches branch keys and beacon keys. Create one with {@link #create(CacheType)} to share it between keyrings
 * (pass it with {@link CacheType#shared}); implement this only for storage the built-in caches do not cover.
 * A cache used from several threads must be thread-safe; the built-in {@link CacheType#singleThreaded} cache is not.
 */
//= spec/framework/cryptographic-materials-cache.md#overview
//= type=implication
//# Cryptographic materials cache (CMC) is used by the [caching cryptographic materials manager (CMM)](caching-cmm.md)
//# to store cryptographic materials for reuse.
//# This document describes the interface that all CMCs MUST implement.
public interface CryptographicMaterialsCache {
  /** The entry for {@code key}, if present and not expired. */
  Optional<CacheEntry> get(CacheKey key);

  //= spec/framework/cryptographic-materials-cache.md#put-cache-entry
  //= type=implication
  //# This operation MUST NOT return the inserted cache entry.
  void put(CacheKey key, CacheEntry entry);

  void remove(CacheKey key);

  /**
   * A built-in cache, or for {@link CacheType#shared} the cache it holds.
   * The {@link CacheType#singleThreaded} cache is the one built-in cache that is not thread-safe.
   */
  static CryptographicMaterialsCache create(CacheType cacheType) {
    throw new UnsupportedOperationException("not implemented yet");
  }
}
