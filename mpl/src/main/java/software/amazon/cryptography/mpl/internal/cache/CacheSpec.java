// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal.cache;

import java.util.function.Function;
import software.amazon.cryptography.mpl.cache.CacheType;
import software.amazon.cryptography.mpl.cache.CryptographicMaterialsCache;
import software.amazon.cryptography.mpl.cache.StormTrackingCache;

/**
 * What a {@link CacheType} describes, for library code (the cache factory, the hierarchical keyring's TTL check).
 * {@code CacheType} registers its reader when it loads.
 */
public final class CacheSpec {

  private static volatile Function<CacheType, CacheSpec> reader;

  public final CacheType.Kind kind;
  /** For {@code SINGLE_THREADED} and {@code MULTI_THREADED}; 0 otherwise. */
  public final int entryCapacity;
  /** For {@code SINGLE_THREADED} and {@code MULTI_THREADED}; 1 otherwise. */
  public final int entryPruningTailSize;
  /** For {@code DEFAULT} (the default tuning, in milliseconds) and {@code STORM_TRACKING}; null otherwise. */
  public final StormTrackingCache stormTracking;
  /** For {@code SHARED}; null otherwise. */
  public final CryptographicMaterialsCache shared;

  private CacheSpec(
    CacheType.Kind kind,
    int entryCapacity,
    int entryPruningTailSize,
    StormTrackingCache stormTracking,
    CryptographicMaterialsCache shared
  ) {
    this.kind = kind;
    this.entryCapacity = entryCapacity;
    this.entryPruningTailSize = entryPruningTailSize;
    this.stormTracking = stormTracking;
    this.shared = shared;
  }

  public static CacheSpec local(CacheType.Kind kind, int entryCapacity, int entryPruningTailSize) {
    return new CacheSpec(kind, entryCapacity, entryPruningTailSize, null, null);
  }

  public static CacheSpec stormTracking(CacheType.Kind kind, StormTrackingCache settings) {
    return new CacheSpec(kind, 0, 1, settings, null);
  }

  public static CacheSpec shared(CryptographicMaterialsCache cache) {
    return new CacheSpec(CacheType.Kind.SHARED, 0, 1, null, cache);
  }

  public static void register(Function<CacheType, CacheSpec> read) {
    reader = read;
  }

  /** Instances exist only once {@code CacheType} has loaded and registered. */
  public static CacheSpec of(CacheType type) {
    return reader.apply(type);
  }
}
