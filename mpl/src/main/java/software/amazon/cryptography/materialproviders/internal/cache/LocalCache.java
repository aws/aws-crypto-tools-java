// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.cache;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Predicate;
import software.amazon.cryptography.materialproviders.cache.CacheKey;

/**
 * An LRU cache with TTL-expired entry pruning, per LocalCMC.dfy. Not thread-safe.
 *
 * <p>A hit moves the entry to the front, then prunes:
 * it removes expired entries from the least recently used end, at most {@code entryPruningTailSize},
 * stopping at the first live one.
 * Reading an expired entry removes it. A capacity of 0 stores nothing.
 */
public final class LocalCache<V> implements CacheEngine<V> {

  //= spec/framework/local-cryptographic-materials-cache.md#entry-capacity
  //= type=implication
  //# The local CMC MUST accept entry capacity values between zero
  //# and an implementation-defined maximum, inclusive.
  private final int entryCapacity;
  //= spec/framework/local-cryptographic-materials-cache.md#entry-pruning-tail-size
  //= type=implication
  //# The _entry pruning tail size_
  //# is the number of least recently used entries that the local CMC
  //# MUST check during [pruning](#pruning)
  //# for TTL-expired entries to evict.
  private final int entryPruningTailSize;
  private final CacheClock clock;
  private final Map<CacheKey, Node<V>> entries = new HashMap<>();
  // head is the most recently used entry, tail the least.
  private Node<V> head;
  private Node<V> tail;

  //= spec/framework/local-cryptographic-materials-cache.md#initialization
  //= type=implication
  //# On initialization of the local CMC,
  //# the caller MUST provide the following:
  //# - [Entry Capacity](#entry-capacity)
  //#
  //# The local CMC MUST also define the following:
  //#
  //# - [Entry Pruning Tail Size](#entry-pruning-tail-size)
  public LocalCache(int entryCapacity, int entryPruningTailSize, CacheClock clock) {
    this.entryCapacity = entryCapacity;
    this.entryPruningTailSize = entryPruningTailSize;
    this.clock = clock;
  }

  @Override
  public Lookup<V> get(CacheKey key) {
    return get(key, clock.wallMillis() / 1000);
  }

  /** An entry is live through the second {@code now == expirySeconds}. */
  Lookup<V> get(CacheKey key, long nowSeconds) {
    Node<V> node = entries.get(key);
    if (node == null) {
      return Lookup.miss(Lookup.MISSING);
    }
    //= spec/framework/cryptographic-materials-cache.md#time-to-live-ttl
    //# After a cache entry's TTL has elapsed,
    //# we say that the entry is _TTL-expired_,
    //# and a CMC MUST NOT return the entry to any caller.
    //
    //= spec/framework/cryptographic-materials-cache.md#get-cache-entry
    //# The CMC MUST validate that the cache entry
    //# has not exceeded it's stored [TTL](#time-to-live-ttl).
    //
    //= spec/framework/local-cryptographic-materials-cache.md#get-cache-entry
    //# The local CMC MUST NOT return any TTL-expired entry.
    if (nowSeconds > node.expirySeconds) {
      remove(key);
      return Lookup.miss(Lookup.EXPIRED);
    }
    moveToFront(node);
    //= spec/framework/local-cryptographic-materials-cache.md#get-cache-entry
    //# When performing a Get Cache Entry operation,
    //# the local CMC MUST [prune TTL-expired cache entries](#pruning).
    prune(nowSeconds);
    return Lookup.hit(node.value, node.expirySeconds);
  }

  @Override
  public void put(CacheKey key, V value, long expirySeconds) {
    if (entryCapacity == 0) {
      return;
    }
    remove(key);
    //= spec/framework/local-cryptographic-materials-cache.md#put-cache-entry
    //# However, before returning the local CMC MUST evict least-recently used entries
    //# until the number of stored entries does not exceed the entry capacity.
    //
    //= spec/framework/local-cryptographic-materials-cache.md#entry-capacity
    //# The local CMC MUST NOT store more entries than this value,
    //# except temporarily while performing a Put Cache Entry operation.
    //
    //= spec/framework/local-cryptographic-materials-cache.md#put-cache-entry
    //= type=exception
    //= reason=The least recently used entry is evicted before the new entry is inserted, so the count never exceeds the capacity.
    //# While performing a Put Cache Entry operation,
    //# the local CMC MAY store more entries than the entry capacity.
    if (entries.size() == entryCapacity) {
      remove(tail.key);
    }
    Node<V> node = new Node<>(key, value, expirySeconds);
    node.next = head;
    if (head != null) {
      head.prev = node;
    } else {
      tail = node;
    }
    head = node;
    entries.put(key, node);
  }

  @Override
  public void remove(CacheKey key) {
    Node<V> node = entries.remove(key);
    if (node != null) {
      unlink(node);
    }
  }

  @Override
  public void retainIf(CacheKey key, Predicate<? super V> keep) {
    Node<V> node = entries.get(key);
    if (node != null && !keep.test(node.value)) {
      remove(key);
    }
  }

  //= spec/framework/local-cryptographic-materials-cache.md#pruning
  //= type=exception
  //= reason=Pruning runs only on a Get Cache Entry hit; there is no periodic background eviction.
  //# The local CMC SHOULD also periodically evict all TTL-expired entries
  //# among the `N` least recently used entries.
  private void prune(long nowSeconds) {
    //= spec/framework/local-cryptographic-materials-cache.md#pruning
    //# To prune TTL-expired cache entries,
    //# the local CMC MUST evict all TTL-expired entries
    //# among the `N` least recently used entries,
    //# where `N` is the [Entry Pruning Tail Size](#entry-pruning-tail-size).
    for (int i = 0; i < entryPruningTailSize; i++) {
      if (tail == null || tail.expirySeconds >= nowSeconds) {
        return;
      }
      remove(tail.key);
    }
  }

  private void moveToFront(Node<V> node) {
    if (node == head) {
      return;
    }
    unlink(node);
    node.next = head;
    head.prev = node;
    head = node;
  }

  private void unlink(Node<V> node) {
    if (node.prev == null) {
      head = node.next;
    } else {
      node.prev.next = node.next;
    }
    if (node.next == null) {
      tail = node.prev;
    } else {
      node.next.prev = node.prev;
    }
    node.prev = null;
    node.next = null;
  }

  private static final class Node<V> {

    final CacheKey key;
    final V value;
    final long expirySeconds;
    Node<V> prev;
    Node<V> next;

    Node(CacheKey key, V value, long expirySeconds) {
      this.key = key;
      this.value = value;
      this.expirySeconds = expirySeconds;
    }
  }
}
