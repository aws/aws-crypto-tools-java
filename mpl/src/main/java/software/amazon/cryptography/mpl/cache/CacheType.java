// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.cache;

/**
 * Which cache a hierarchical keyring uses: a private cache it builds from these settings, or a shared instance.
 * Create one with the static methods. Immutable.
 *
 * <p>The keyring checks its TTL against the cache only for {@link #stormTracking}, and, when no cache is configured,
 * against the default storm-tracking settings: the TTL must exceed the grace period.
 * {@link #defaultCache}, {@link #noCache}, {@link #singleThreaded}, {@link #multiThreaded}, and {@link #shared}
 * are not checked. So a keyring given {@code defaultCache} explicitly accepts a TTL at or below its 10-second grace period,
 * which the same keyring without a cache rejects. Each branch key it caches is then inside the grace period as soon as it is
 * cached, so the cache saves few key store reads: a read while no refresh of the key is in flight is a miss and reads the key store,
 * and only reads during such a refresh (at most one grace interval, 1 second) get the cached key.
 *
 * <p>Entry capacities and pruning tail sizes must be at least 1; the factories throw
 * {@link software.amazon.cryptography.mpl.exceptions.ValidationException} otherwise.
 */
public abstract class CacheType {

  /** The kinds, for {@code switch}. More kinds may be added; include a {@code default} branch. */
  public enum Kind {
    DEFAULT,
    NO_CACHE,
    SINGLE_THREADED,
    MULTI_THREADED,
    STORM_TRACKING,
    SHARED,
  }

  private CacheType() {}

  /**
   * A storm-tracking cache with default tuning and {@code entryCapacity} entries, timed in milliseconds:
   * a 10-second grace period, 1-second grace interval, fan-out 20, and 10-second in-flight TTL.
   * {@link StormTrackingCache.Builder}'s defaults give the same durations in {@link TimeUnits#SECONDS} (10, 1, and 10).
   */
  public static CacheType defaultCache(int entryCapacity) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** Caches nothing: every operation reads the key store. */
  public static CacheType noCache() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** An LRU cache for use from one thread at a time. */
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
  public static CacheType singleThreaded(int entryCapacity) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** {@link #singleThreaded(int)} that prunes {@code entryPruningTailSize} expired entries per pass instead of 1. */
  public static CacheType singleThreaded(int entryCapacity, int entryPruningTailSize) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** A thread-safe LRU cache. */
  public static CacheType multiThreaded(int entryCapacity) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** {@link #multiThreaded(int)} that prunes {@code entryPruningTailSize} expired entries per pass instead of 1. */
  public static CacheType multiThreaded(int entryCapacity, int entryPruningTailSize) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  public static CacheType stormTracking(StormTrackingCache settings) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** An existing cache, shared with every keyring given the same instance; entries are separated by partition id. */
  public static CacheType shared(CryptographicMaterialsCache cache) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  public abstract Kind kind();

  private static CacheType local(Kind kind, int entryCapacity, int entryPruningTailSize) {
    throw new UnsupportedOperationException("not implemented yet");
  }
}
