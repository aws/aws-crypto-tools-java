// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.cache;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.materialproviders.cache.CacheKey;

// LocalCMC.dfy behavior with explicit times (seconds), including the Dafny LocalCMCBasics test.
class LocalCacheTest {

  private final TestClock clock = new TestClock(0);

  //= spec/framework/local-cryptographic-materials-cache.md#get-cache-entry
  //= type=test
  //# The local CMC MUST NOT return any TTL-expired entry.
  //
  //= spec/framework/cryptographic-materials-cache.md#time-to-live-ttl
  //= type=test
  //# After a cache entry's TTL has elapsed,
  //# we say that the entry is _TTL-expired_,
  //# and a CMC MUST NOT return the entry to any caller.
  @Test
  void dafnyLocalCmcBasics() {
    LocalCache<String> cache = new LocalCache<>(100, 1, clock);
    assertEquals(Lookup.MISSING, cache.get(key("abc"), 10000).missReason());
    cache.put(key("abc"), "abc", 10000);
    cache.put(key("cde"), "cde", 10000);
    assertEquals("abc", cache.get(key("abc"), 9999).value());
    assertEquals("abc", cache.get(key("abc"), 10000).value());
    assertEquals(Lookup.EXPIRED, cache.get(key("abc"), 10001).missReason());
    assertEquals("cde", cache.get(key("cde"), 9999).value());
    cache.remove(key("cde"));
    assertEquals(Lookup.MISSING, cache.get(key("abc"), 9999).missReason());
    cache.remove(key("cde"));
  }

  // LocalCMC moves a hit to the front before pruning, so the prune sees the next least recently used entry.
  @Test
  void aHitIsMovedToTheFrontBeforeThePrune() {
    LocalCache<String> cache = new LocalCache<>(10, 1, clock);
    cache.put(key("a"), "a", 100);
    cache.put(key("b"), "b", 5);
    cache.put(key("c"), "c", 100);
    assertTrue(cache.get(key("a"), 6).isHit());
    assertEquals(Lookup.MISSING, cache.get(key("b"), 6).missReason());
  }

  // Replacing a key in a full cache removes the old entry first, so nothing else is evicted.
  @Test
  void replacingAKeyInAFullCacheEvictsNothing() {
    LocalCache<String> cache = new LocalCache<>(2, 1, clock);
    cache.put(key("a"), "a", 100);
    cache.put(key("b"), "b", 100);
    cache.put(key("b"), "b2", 100);
    assertEquals("a", cache.get(key("a"), 1).value());
    assertEquals("b2", cache.get(key("b"), 1).value());
  }

  @Test
  void anExpiredReadRemovesTheEntry() {
    LocalCache<String> cache = new LocalCache<>(10, 1, clock);
    cache.put(key("a"), "a", 5);
    assertEquals(Lookup.EXPIRED, cache.get(key("a"), 6).missReason());
    assertEquals(Lookup.MISSING, cache.get(key("a"), 5).missReason());
  }

  @Test
  void readsTheClockInWholeSeconds() {
    LocalCache<String> cache = new LocalCache<>(10, 1, clock);
    cache.put(key("a"), "a", 10);
    clock.set(10_999);
    assertTrue(cache.get(key("a")).isHit());
    clock.set(11_000);
    assertEquals(Lookup.EXPIRED, cache.get(key("a")).missReason());
  }

  @Test
  void hitReportsItsExpiry() {
    LocalCache<String> cache = new LocalCache<>(10, 1, clock);
    cache.put(key("a"), "a", 42);
    assertEquals(42, cache.get(key("a"), 1).expirySeconds());
  }

  //= spec/framework/local-cryptographic-materials-cache.md#put-cache-entry
  //= type=test
  //# However, before returning the local CMC MUST evict least-recently used entries
  //# until the number of stored entries does not exceed the entry capacity.
  //
  //= spec/framework/local-cryptographic-materials-cache.md#entry-capacity
  //= type=test
  //# The local CMC MUST NOT store more entries than this value,
  //# except temporarily while performing a Put Cache Entry operation.
  @Test
  void evictsTheLeastRecentlyUsed() {
    LocalCache<String> cache = new LocalCache<>(3, 1, clock);
    put(cache, "a", "b", "c");
    cache.get(key("a"), 0);
    cache.put(key("d"), "d", 100);
    assertEquals(Lookup.MISSING, cache.get(key("b"), 0).missReason());
    // Replacing an entry makes it the most recent and keeps the count.
    cache.put(key("c"), "c2", 100);
    cache.put(key("e"), "e", 100);
    assertEquals(list("c", "d", "e"), present(cache, "a", "b", "c", "d", "e"));
    assertEquals("c2", cache.get(key("c"), 0).value());
  }

  // The replaced entry's old position must go: otherwise evicting it would drop the new value.
  @Test
  void replacingAnEntryRemovesItsOldPosition() {
    LocalCache<String> cache = new LocalCache<>(3, 1, clock);
    put(cache, "a", "b");
    cache.put(key("a"), "a2", 100);
    put(cache, "c", "d");
    assertEquals(list("a", "c", "d"), present(cache, "a", "b", "c", "d"));
    assertEquals("a2", cache.get(key("a"), 0).value());
  }

  //= spec/framework/local-cryptographic-materials-cache.md#entry-capacity
  //= type=test
  //# The local CMC MUST accept entry capacity values between zero
  //# and an implementation-defined maximum, inclusive.
  @Test
  void capacityOneAndZero() {
    LocalCache<String> one = new LocalCache<>(1, 1, clock);
    put(one, "a", "b");
    assertEquals(list("b"), present(one, "a", "b"));
    one.put(key("b"), "b2", 100);
    assertEquals("b2", one.get(key("b"), 0).value());
    LocalCache<String> zero = new LocalCache<>(0, 1, clock);
    put(zero, "a");
    assertEquals(Lookup.MISSING, zero.get(key("a"), 0).missReason());
    zero.remove(key("a"));
  }

  //= spec/framework/local-cryptographic-materials-cache.md#get-cache-entry
  //= type=test
  //# When performing a Get Cache Entry operation,
  //# the local CMC MUST [prune TTL-expired cache entries](#pruning).
  //
  //= spec/framework/local-cryptographic-materials-cache.md#pruning
  //= type=test
  //# To prune TTL-expired cache entries,
  //# the local CMC MUST evict all TTL-expired entries
  //# among the `N` least recently used entries,
  //# where `N` is the [Entry Pruning Tail Size](#entry-pruning-tail-size).
  @Test
  void aHitPrunesExpiredEntriesFromTheTail() {
    for (int tail = 1; tail <= 5; tail++) {
      LocalCache<String> cache = new LocalCache<>(10, tail, clock);
      for (String id : new String[] { "e1", "e2", "e3", "e4" }) {
        cache.put(key(id), id, 5);
      }
      cache.put(key("live"), "live", 100);
      cache.get(key("live"), 10);
      for (int i = 1; i <= 4; i++) {
        String expected = i <= tail ? Lookup.MISSING : Lookup.EXPIRED;
        assertEquals(expected, cache.get(key("e" + i), 10).missReason(), "tail " + tail + " e" + i);
      }
    }
  }

  @Test
  void pruningStopsAtALiveTail() {
    LocalCache<String> cache = new LocalCache<>(10, 5, clock);
    cache.put(key("expired"), "x", 5);
    cache.put(key("live"), "l", 100);
    cache.put(key("expired2"), "y", 5);
    cache.put(key("hot"), "h", 100);
    cache.get(key("hot"), 10);
    assertEquals(Lookup.MISSING, cache.get(key("expired"), 10).missReason());
    assertEquals(Lookup.EXPIRED, cache.get(key("expired2"), 10).missReason());
  }

  @Test
  void pruningKeepsAnEntryExpiringNow() {
    LocalCache<String> cache = new LocalCache<>(10, 1, clock);
    cache.put(key("edge"), "edge", 10);
    cache.put(key("live"), "live", 100);
    cache.get(key("live"), 10);
    assertTrue(cache.get(key("edge"), 10).isHit());
  }

  @Test
  void aMissDoesNotPrune() {
    LocalCache<String> cache = new LocalCache<>(10, 1, clock);
    cache.put(key("old"), "old", 5);
    cache.get(key("missing"), 10);
    assertEquals(Lookup.EXPIRED, cache.get(key("old"), 10).missReason());
  }

  @Test
  void retainIfKeepsTheLruPosition() {
    LocalCache<String> cache = new LocalCache<>(2, 1, clock);
    put(cache, "a", "b");
    List<String> seen = new ArrayList<>();
    cache.retainIf(key("a"), value -> seen.add(value));
    cache.retainIf(key("missing"), value -> seen.add(value));
    assertEquals(list("a"), seen);
    cache.put(key("c"), "c", 100);
    assertEquals(list("b", "c"), present(cache, "a", "b", "c"));
    cache.retainIf(key("b"), value -> false);
    assertEquals(list("c"), present(cache, "a", "b", "c"));
  }

  @Test
  void retainIfIgnoresExpiry() {
    LocalCache<String> cache = new LocalCache<>(2, 1, clock);
    cache.put(key("a"), "a", 0);
    clock.set(1_000_000);
    cache.retainIf(key("a"), value -> true);
    assertEquals(Lookup.EXPIRED, cache.get(key("a"), 1).missReason());
  }

  @Test
  void keysCompareByBytes() {
    LocalCache<String> cache = new LocalCache<>(2, 1, clock);
    byte[] bytes = "k".getBytes(StandardCharsets.UTF_8);
    cache.put(CacheKey.of(bytes), "k", 100);
    assertEquals("k", cache.get(CacheKey.of("k".getBytes(StandardCharsets.UTF_8)), 0).value());
    cache.remove(CacheKey.of(bytes.clone()));
    assertFalse(cache.get(key("k"), 0).isHit());
    assertNull(cache.get(key("k"), 0).value());
  }

  private static void put(LocalCache<String> cache, String... ids) {
    for (String id : ids) {
      cache.put(key(id), id, 100);
    }
  }

  // The ids still present, in argument order. Reading them changes the LRU order, so call this last.
  private static List<String> present(LocalCache<String> cache, String... ids) {
    List<String> present = new ArrayList<>();
    for (String id : ids) {
      if (cache.get(key(id), 0).isHit()) {
        present.add(id);
      }
    }
    return present;
  }

  private static List<String> list(String... ids) {
    List<String> list = new ArrayList<>();
    for (String id : ids) {
      list.add(id);
    }
    return list;
  }

  static CacheKey key(String id) {
    return CacheKey.of(id.getBytes(StandardCharsets.UTF_8));
  }
}
