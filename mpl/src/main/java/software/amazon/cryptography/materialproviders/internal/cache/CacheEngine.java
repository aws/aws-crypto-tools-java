// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.cache;

import java.util.function.Predicate;
import software.amazon.cryptography.materialproviders.cache.CacheKey;

/**
 * A built-in cache over any value type: the public cache stores {@code CacheEntry},
 * and the test adapter stores the Dafny-based MPL's entries, which also carry usage counters.
 * Expiry is in whole seconds since the epoch, as in the Dafny-based caches.
 */
public interface CacheEngine<V> {
  /** @throws software.amazon.cryptography.materialproviders.exceptions.ThrottlingException when a storm-tracking wait times out */
  Lookup<V> get(CacheKey key);

  void put(CacheKey key, V value, long expirySeconds);

  void remove(CacheKey key);

  /**
   * Runs {@code keep} on the entry for {@code key}, if there is one, without changing its LRU position or checking expiry;
   * removes the entry when {@code keep} returns false. Atomic in the thread-safe caches.
   */
  void retainIf(CacheKey key, Predicate<? super V> keep);
}
