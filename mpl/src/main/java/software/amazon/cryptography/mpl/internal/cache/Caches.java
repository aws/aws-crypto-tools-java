// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal.cache;

import software.amazon.cryptography.mpl.cache.CacheType;
import software.amazon.cryptography.mpl.exceptions.InternalException;

/** Builds the cache a {@link CacheType} names, per CreateCryptographicMaterialsCache in AwsCryptographyMaterialProvidersOperations.dfy. */
public final class Caches {

  private Caches() {}

  /** Not for {@code SHARED}, which already is a cache. */
  public static <V> CacheEngine<V> engine(CacheType type, CacheClock clock) {
    CacheSpec spec = CacheSpec.of(type);
    switch (spec.kind) {
      case DEFAULT:
      case STORM_TRACKING:
        return new StormTracker<>(spec.stormTracking, clock);
      case NO_CACHE:
        return new LocalCache<>(0, 1, clock);
      case SINGLE_THREADED:
        return new LocalCache<>(spec.entryCapacity, spec.entryPruningTailSize, clock);
      case MULTI_THREADED:
        return new SynchronizedCache<>(new LocalCache<>(spec.entryCapacity, spec.entryPruningTailSize, clock));
      default:
        throw new InternalException("No cache engine for kind " + spec.kind);
    }
  }
}
