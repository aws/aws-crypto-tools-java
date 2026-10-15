// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal.cache;

import java.util.Objects;
import java.util.Optional;
import software.amazon.cryptography.mpl.cache.CacheEntry;
import software.amazon.cryptography.mpl.cache.CacheKey;
import software.amazon.cryptography.mpl.cache.CryptographicMaterialsCache;

/** The public cache interface over a built-in cache. */
public final class BuiltInCache implements CryptographicMaterialsCache {

  private final CacheEngine<CacheEntry> engine;

  public BuiltInCache(CacheEngine<CacheEntry> engine) {
    this.engine = engine;
  }

  @Override
  public Optional<CacheEntry> get(CacheKey key) {
    Objects.requireNonNull(key, "key");
    return Optional.ofNullable(engine.get(key).value());
  }

  @Override
  public void put(CacheKey key, CacheEntry entry) {
    Objects.requireNonNull(key, "key");
    engine.put(key, entry, entry.expiryTime().getEpochSecond());
  }

  @Override
  public void remove(CacheKey key) {
    Objects.requireNonNull(key, "key");
    engine.remove(key);
  }
}
