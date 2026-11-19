// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.cache;

/**
 * Caches branch keys and beacon keys. The built-in caches are {@link DefaultCache}, {@link StormTrackingCache},
 * {@link MultiThreadedCache}, {@link SingleThreadedCache}, and {@link NoCache};
 * implement this only for storage they do not cover.
 * Keyrings given the same instance share it; a cache used from several threads must be thread-safe,
 * which {@link SingleThreadedCache} is not.
 *
 * <p>Each method takes a request object and returns a response object,
 * so a later version can add fields to either without breaking caches that callers implement.
 */
//= spec/framework/cryptographic-materials-cache.md#overview
//= type=implication
//# Cryptographic materials cache (CMC) is used by the [caching cryptographic materials manager (CMM)](caching-cmm.md)
//# to store cryptographic materials for reuse.
//# This document describes the interface that all CMCs MUST implement.
public interface CryptographicMaterialsCache {
  /** The entry for the request's key, if present and not expired; a miss is an empty response, not an exception. */
  GetCacheEntryResponse getCacheEntry(GetCacheEntryRequest request);

  //= spec/framework/cryptographic-materials-cache.md#put-cache-entry
  //= type=implication
  //# This operation MUST NOT return the inserted cache entry.
  //
  //= spec/framework/cryptographic-materials-cache.md#put-cache-entry
  //= type=exception
  //= reason=Cache entries carry no usage metadata; the branch key and beacon key caches never read it.
  //# The cache entry MUST include all [usage metadata](#usage-metadata)
  //# since this information can not be updated after the put operation.
  PutCacheEntryResponse putCacheEntry(PutCacheEntryRequest request);

  DeleteCacheEntryResponse deleteCacheEntry(DeleteCacheEntryRequest request);
}
