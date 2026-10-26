// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.cache;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Predicate;
import software.amazon.cryptography.materialproviders.cache.CacheKey;
import software.amazon.cryptography.materialproviders.cache.StormTrackingCache;
import software.amazon.cryptography.materialproviders.exceptions.ThrottlingException;

/**
 * A thread-safe {@link LocalCache} that limits concurrent refreshes, per StormTracker.dfy and StormTrackingCMC.java.
 *
 * <p>A read either returns the entry, tells the caller to fetch (a miss), or makes it wait:
 * <ul>
 *   <li>Entry present, outside the grace period before expiry: returned.
 *   <li>Entry present, inside the grace period: a miss for one caller per grace interval, which refreshes it;
 *       everyone else gets the entry.
 *   <li>Entry absent: a miss for one caller per grace interval; everyone else waits.
 *   <li>{@code fanOut} keys already in flight: present entries are returned, absent ones wait.
 * </ul>
 * A key stops being in flight when it is put or removed, or, once fanOut is reached, after inFlightTtl.
 * A waiting caller re-checks every {@code sleepMilli}, or sooner when an entry is put or removed,
 * and fails with {@link ThrottlingException} once it has waited longer than inFlightTtl.
 */
public final class StormTracker<V> implements CacheEngine<V> {

  // The largest expiry, in seconds, whose value in milliseconds fits in a long (StormTracker.dfy GracePeriod?).
  private static final long MAX_EXPIRY_SECONDS = 0x20C49BA5E353F7L;
  private static final String WAIT_EXCEEDED = "Storm cache inFlightTTL exceeded.";

  private final Object lock = new Object();
  private final LocalCache<V> wrapped;
  private final CacheClock clock;
  // Monotonic time at which each key went in flight.
  private final Map<CacheKey, Long> inFlight = new HashMap<>();
  // All in milliseconds.
  private final long gracePeriod;
  private final long graceInterval;
  private final long inFlightTtl;
  private final long sleepMilli;
  private final int fanOut;
  // Long.MIN_VALUE lets the first prune run whatever the monotonic clock's origin.
  private long lastPrune = Long.MIN_VALUE;

  public StormTracker(StormTrackingCache cache, CacheClock clock) {
    StormSettings settings = StormSettings.of(cache);
    this.wrapped = new LocalCache<>(settings.entryCapacity, settings.entryPruningTailSize, clock);
    this.clock = clock;
    this.gracePeriod = settings.gracePeriodMillis();
    this.graceInterval = settings.graceIntervalMillis();
    this.inFlightTtl = settings.inFlightTtlMillis();
    this.sleepMilli = settings.sleepMilli;
    this.fanOut = settings.fanOut;
  }

  @Override
  public Lookup<V> get(CacheKey key) {
    // The wait limit counts from the call, including time spent waiting for the lock.
    long waitUntil = add(clock.monotonicMillis(), inFlightTtl);
    synchronized (lock) {
      while (true) {
        long wallNow = clock.wallMillis();
        long now = clock.monotonicMillis();
        Lookup<V> cached = wrapped.get(key, wallNow / 1000);
        if (cached.isHit()) {
          return refreshDue(key, cached.expirySeconds(), wallNow, now) ? Lookup.miss(Lookup.MISSING) : cached;
        }
        if (fetchDue(key, now)) {
          return Lookup.miss(Lookup.MISSING);
        }
        if (clock.monotonicMillis() > waitUntil) {
          throw new ThrottlingException(WAIT_EXCEEDED);
        }
        try {
          lock.wait(sleepMilli);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          throw new ThrottlingException("Storm cache wait was interrupted.", e);
        }
      }
    }
  }

  @Override
  public void put(CacheKey key, V value, long expirySeconds) {
    synchronized (lock) {
      inFlight.remove(key);
      wrapped.put(key, value, expirySeconds);
      lock.notifyAll();
    }
  }

  @Override
  public void remove(CacheKey key) {
    synchronized (lock) {
      inFlight.remove(key);
      wrapped.remove(key);
      lock.notifyAll();
    }
  }

  @Override
  public void retainIf(CacheKey key, Predicate<? super V> keep) {
    synchronized (lock) {
      wrapped.retainIf(key, keep);
    }
  }

  // CheckInFlight: whether this caller must refresh a present entry.
  private boolean refreshDue(CacheKey key, long expirySeconds, long wallNow, long now) {
    if (fanOutReached(now) || !inGracePeriod(expirySeconds, wallNow)) {
      return false;
    }
    Long since = inFlight.get(key);
    if (since != null && add(since, graceInterval) > now) {
      return false;
    }
    inFlight.put(key, now);
    return true;
  }

  // CheckNewEntry: whether this caller must fetch an absent entry; false means wait.
  private boolean fetchDue(CacheKey key, long now) {
    if (fanOutReached(now)) {
      return false;
    }
    Long since = inFlight.get(key);
    if (since != null && now < add(since, graceInterval)) {
      return false;
    }
    inFlight.put(key, now);
    return true;
  }

  private boolean inGracePeriod(long expirySeconds, long wallNow) {
    return expirySeconds < MAX_EXPIRY_SECONDS && expirySeconds * 1000 - gracePeriod <= wallNow;
  }

  private boolean fanOutReached(long now) {
    pruneInFlight(now);
    return fanOut <= inFlight.size();
  }

  // Forgets keys in flight longer than inFlightTtl; only when fanOut is reached, and at most once a second.
  private void pruneInFlight(long now) {
    if (inFlight.size() < fanOut || now - 1000 < lastPrune) {
      return;
    }
    lastPrune = now;
    inFlight.values().removeIf(since -> now >= add(since, inFlightTtl));
  }

  // StormTracker.dfy AddLong: saturates instead of overflowing.
  private static long add(long x, long y) {
    return x < Long.MAX_VALUE - y ? x + y : Long.MAX_VALUE;
  }
}
