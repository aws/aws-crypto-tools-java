// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.cache;

import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

/** The built-in cache engines, per CreateCryptographicMaterialsCache in AwsCryptographyMaterialProvidersOperations.dfy. */
public final class Caches {

  /** The entry capacity of the cache a hierarchical keyring builds when none is set. */
  public static final int KEYRING_DEFAULT_ENTRY_CAPACITY = 1000;

  private Caches() {}

  /**
   * StormTracker.dfy DefaultStorm, with its times in milliseconds.
   *
   * @throws ValidationException if {@code entryCapacity} is below 1
   */
  public static StormSettings defaultSettings(int entryCapacity) {
    return StormSettings.create(entryCapacity, 1, 10 * 1000, 1 * 1000, 20, 10 * 1000, 20, false);
  }

  public static <V> CacheEngine<V> noCache(CacheClock clock) {
    return new LocalCache<>(0, 1, clock);
  }

  public static <V> CacheEngine<V> singleThreaded(int entryCapacity, int entryPruningTailSize, CacheClock clock) {
    return new LocalCache<>(entryCapacity, entryPruningTailSize, clock);
  }

  public static <V> CacheEngine<V> multiThreaded(int entryCapacity, int entryPruningTailSize, CacheClock clock) {
    return new SynchronizedCache<>(new LocalCache<>(entryCapacity, entryPruningTailSize, clock));
  }

  public static <V> CacheEngine<V> stormTracking(StormSettings settings, CacheClock clock) {
    return new StormTracker<>(settings, clock);
  }

  /**
   * The checks of the local caches' settings.
   *
   * @throws ValidationException if {@code entryCapacity} was not set or either number is below 1
   */
  public static void checkLocal(Integer entryCapacity, int entryPruningTailSize) {
    if (entryCapacity == null) {
      throw new ValidationException("Missing value for required field `entryCapacity`");
    }
    StormSettings.atLeastOne("entryCapacity", entryCapacity);
    StormSettings.atLeastOne("entryPruningTailSize", entryPruningTailSize);
  }
}
