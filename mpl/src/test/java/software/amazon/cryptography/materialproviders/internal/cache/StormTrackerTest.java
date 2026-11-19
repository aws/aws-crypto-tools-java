// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.cache;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.materialproviders.internal.cache.LocalCacheTest.key;

import java.time.Duration;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import software.amazon.cryptography.materialproviders.cache.StormTrackingCache;
import software.amazon.cryptography.materialproviders.exceptions.ThrottlingException;

// StormTracker.dfy and StormTrackingCMC.java behavior on an injected clock.
// The first tests port test/CMCs/StormTracker.dfy step for step: each step sets the clock to the Dafny `now`
// (milliseconds) and checks the state Dafny's GetFromCacheWithTime returns.
// Full and Fetch are a hit and a miss; Wait is a caller parked until something changes, seen here by interrupting it.
@Timeout(60)
class StormTrackerTest {

  private enum State {
    FULL,
    FETCH,
    WAIT,
  }

  private final TestClock clock = new TestClock(0);

  // StormTracker.dfy DefaultStorm.
  private static StormTrackingCache.Builder defaultStorm() {
    return StormTrackingCache
      .builder()
      .entryCapacity(1000)
      .entryPruningTailSize(1)
      .gracePeriod(Duration.ofMillis(10 * 1000))
      .graceInterval(Duration.ofMillis(1 * 1000))
      .fanOut(20)
      .inFlightTtl(Duration.ofMillis(10 * 1000))
      .sleep(Duration.ofMillis(20));
  }

  @Test
  void dafnyStormTrackerBasics() {
    StormTracker<String> st = new StormTracker<>(StormSettings.of(defaultStorm().build()), clock);
    assertEquals(State.FETCH, poll(st, "abc", 10000));
    assertEquals(State.WAIT, poll(st, "abc", 10000));
    st.put(key("abc"), "abc", 10000 / 1000);
    st.put(key("cde"), "cde", 10000 / 1000);
    assertEquals(State.FETCH, poll(st, "abc", 11000));
    assertEquals(State.WAIT, poll(st, "abc", 11000));
    st.remove(key("abc"));
    st.remove(key("abc"));
  }

  @Test
  void dafnyStormTrackerFanOut() {
    StormTracker<String> st = new StormTracker<>(StormSettings.of(defaultStorm().fanOut(3).build()), clock);
    assertEquals(State.FETCH, poll(st, "one", 10000));
    assertEquals(State.FETCH, poll(st, "two", 10000));
    assertEquals(State.FETCH, poll(st, "three", 10000));
    assertEquals(State.WAIT, poll(st, "four", 10000));
  }

  @Test
  void dafnyStormTrackerPruneTTL() {
    StormTracker<String> st = new StormTracker<>(StormSettings.of(defaultStorm().graceInterval(Duration.ofMillis(3)).fanOut(3).inFlightTtl(Duration.ofMillis(5)).build()), clock);
    assertEquals(State.FETCH, poll(st, "one", 10000));
    assertEquals(State.FETCH, poll(st, "two", 10000));
    assertEquals(State.FETCH, poll(st, "three", 10000));
    assertEquals(State.WAIT, poll(st, "four", 10000));
    assertEquals(State.WAIT, poll(st, "four", 10001));
    assertEquals(State.WAIT, poll(st, "four", 10003));
    // fanOut is reached and nothing was put, so only the once-a-second prune frees a slot.
    assertEquals(State.FETCH, poll(st, "four", 11000));
  }

  @Test
  void dafnyStormTrackerGraceInterval() {
    StormTracker<String> st = new StormTracker<>(StormSettings.of(defaultStorm().graceInterval(Duration.ofMillis(3)).build()), clock);
    assertEquals(State.FETCH, poll(st, "one", 10000));
    assertEquals(State.WAIT, poll(st, "one", 10000));
    assertEquals(State.WAIT, poll(st, "one", 10001));
    assertEquals(State.WAIT, poll(st, "one", 10002));
    assertEquals(State.FETCH, poll(st, "one", 10003));
  }

  @Test
  void dafnyFullStormTrackerGraceInterval() {
    StormTracker<String> st = new StormTracker<>(StormSettings.of(defaultStorm().graceInterval(Duration.ofMillis(2)).inFlightTtl(Duration.ofMillis(3)).gracePeriod(Duration.ofMillis(5)).build()), clock);
    // Live until millisecond 10999.
    st.put(key("one"), "one", 10000 / 1000);
    assertEquals(State.FETCH, poll(st, "one", 11000 - 5));
    assertEquals(State.FULL, poll(st, "one", 11000 - 5));
    assertEquals(State.FULL, poll(st, "one", 11000 - 4));
    assertEquals(State.FETCH, poll(st, "one", 11000 - 3));
    assertEquals(State.FULL, poll(st, "one", 11000 - 2));
    assertEquals(State.FETCH, poll(st, "one", 11000 - 1));
    assertEquals(State.FULL, poll(st, "one", 11000 - 1));
    // Expired now, and in flight since 10999.
    assertEquals(State.WAIT, poll(st, "one", 11000));
    assertEquals(State.FETCH, poll(st, "one", 11000 + 1));
  }

  @Test
  void dafnyStormTrackerGracePeriod() {
    StormTrackingCache config = defaultStorm().build();
    long expiryTime = 100100;
    // Expiry is stored in seconds, so one millisecond earlier is not before the grace period; a second is.
    long beforeGracePeriod = expiryTime - config.gracePeriod().toMillis() - 1000;
    long insideGracePeriod = expiryTime - config.gracePeriod().toMillis() + 1;
    StormTracker<String> st = new StormTracker<>(StormSettings.of(config), clock);
    st.put(key("one"), "one", expiryTime / 1000);
    assertEquals(State.FULL, poll(st, "one", beforeGracePeriod));
    assertEquals(State.FETCH, poll(st, "one", insideGracePeriod));
    assertEquals(State.FULL, poll(st, "one", insideGracePeriod));
  }

  @Test
  void dafnyEmptyStormTrackerTtlAndInterval() {
    StormTracker<String> st = new StormTracker<>(StormSettings.of(defaultStorm().graceInterval(Duration.ofMillis(2)).inFlightTtl(Duration.ofMillis(3)).build()), clock);
    assertEquals(State.FETCH, poll(st, "one", 10000));
    assertEquals(State.WAIT, poll(st, "one", 10000));
    assertEquals(State.WAIT, poll(st, "one", 10001));
    assertEquals(State.FETCH, poll(st, "one", 10002));
    assertEquals(State.WAIT, poll(st, "one", 10002));
    assertEquals(State.WAIT, poll(st, "one", 10003));
  }

  @Test
  void gracePeriodBoundary() {
    // The Dafny-based settings' Milliseconds unit.
    StormTracker<String> st = new StormTracker<>(StormSettings.create(1000, 1, 2000, 1000, 20, 1000, 20, false), clock);
    st.put(key("a"), "a", 100);
    assertEquals(State.FULL, poll(st, "a", 97_999));
    assertEquals(State.FETCH, poll(st, "a", 98_000));
  }

  @Test
  void secondsMultiplyByAThousand() {
    // The Dafny-based settings' Seconds unit: gracePeriodBoundary's grace period and interval, in seconds.
    StormTracker<String> st = new StormTracker<>(StormSettings.create(1000, 1, 2, 1, 20, 2, 20, true), clock);
    st.put(key("a"), "a", 100);
    assertEquals(State.FULL, poll(st, "a", 97_999));
    assertEquals(State.FETCH, poll(st, "a", 98_000));
    // In flight for less than the 1 second grace interval.
    assertEquals(State.FULL, poll(st, "a", 98_999));
    assertEquals(State.FETCH, poll(st, "a", 99_000));
  }

  // An expiry whose milliseconds overflow a long is never in the grace period.
  @Test
  void largeExpiryIsNeverInTheGracePeriod() {
    long limit = 0x20C49BA5E353F7L;
    StormTracker<String> st = new StormTracker<>(StormSettings.of(defaultStorm().build()), clock);
    st.put(key("max"), "max", Long.MAX_VALUE);
    st.put(key("limit"), "limit", limit);
    st.put(key("below"), "below", limit - 1);
    long late = (limit - 1) * 1000;
    assertEquals(State.FULL, poll(st, "max", late));
    assertEquals(State.FULL, poll(st, "limit", late));
    assertEquals(State.FETCH, poll(st, "below", late));
  }

  // StormTracker.dfy AddLong: in-flight deadlines saturate instead of wrapping.
  @Test
  void inFlightTimesSaturate() {
    StormTracker<String> st = new StormTracker<>(StormSettings.of(defaultStorm().build()), clock);
    long nearMax = Long.MAX_VALUE - 5;
    clock.setWall(10_000);
    clock.setMonotonic(nearMax);
    assertEquals(State.FETCH, pollAt(st, "a"));
    assertEquals(State.WAIT, pollAt(st, "a"));
  }

  // Durations use the monotonic clock: a wall-clock step back does not keep a key in flight.
  @Test
  void inFlightUsesTheMonotonicClock() {
    StormTracker<String> st = new StormTracker<>(StormSettings.of(defaultStorm().build()), clock);
    assertEquals(State.FETCH, poll(st, "a", 10_000_000));
    clock.setWall(10_000_000 - 3_600_000);
    clock.setMonotonic(10_000_000 + 1000);
    assertEquals(State.FETCH, pollAt(st, "a"));
  }

  // With fanOut keys in flight, an entry inside the grace period is returned, not refreshed.
  @Test
  void fanOutReachedReturnsEntriesInTheGracePeriod() {
    StormTracker<String> st = new StormTracker<>(StormSettings.of(defaultStorm().fanOut(1).build()), clock);
    st.put(key("a"), "a", 15);
    assertEquals(State.FETCH, poll(st, "b", 10_000));
    assertEquals(State.FULL, poll(st, "a", 10_000));
    st.remove(key("b"));
    assertEquals(State.FETCH, poll(st, "a", 10_000));
  }

  // In-flight keys are pruned only when fanOut is reached, so a prune below fanOut cannot use up the once-a-second window.
  @Test
  void pruningWaitsForFanOut() {
    StormTracker<String> st = new StormTracker<>(StormSettings.of(defaultStorm().graceInterval(Duration.ofMillis(500)).inFlightTtl(Duration.ofMillis(500)).fanOut(2).build()), clock);
    assertEquals(State.FETCH, poll(st, "a", 10_000));
    assertEquals(State.FETCH, poll(st, "b", 10_500));
    // fanOut reached: a has been in flight for 900 ms, so the prune frees its slot.
    assertEquals(State.FETCH, poll(st, "c", 10_900));
  }

  // A key in flight for exactly inFlightTtl is pruned.
  @Test
  void pruningRemovesKeysAtInFlightTtl() {
    StormTracker<String> st = new StormTracker<>(StormSettings.of(defaultStorm().graceInterval(Duration.ofMillis(500)).inFlightTtl(Duration.ofMillis(500)).fanOut(1).build()), clock);
    assertEquals(State.FETCH, poll(st, "a", 10_000));
    assertEquals(State.WAIT, poll(st, "b", 10_499));
    StormTracker<String> second = new StormTracker<>(StormSettings.of(defaultStorm().graceInterval(Duration.ofMillis(500)).inFlightTtl(Duration.ofMillis(500)).fanOut(1).build()), clock);
    assertEquals(State.FETCH, poll(second, "a", 10_000));
    assertEquals(State.FETCH, poll(second, "b", 10_500));
  }

  // The first prune runs whatever the monotonic clock reads, even less than a second.
  @Test
  void firstPruneRunsNearTheClockOrigin() {
    StormTracker<String> st = new StormTracker<>(StormSettings.of(defaultStorm().graceInterval(Duration.ofMillis(5)).inFlightTtl(Duration.ofMillis(5)).fanOut(1).build()), clock);
    assertEquals(State.FETCH, poll(st, "a", 100));
    assertEquals(State.FETCH, poll(st, "b", 200));
  }

  // A hit prunes up to entryPruningTailSize expired entries; retainIf, which ignores expiry, shows which are left.
  @Test
  void aHitPrunesWithTheConfiguredTailSize() {
    StormTracker<String> st = new StormTracker<>(StormSettings.of(defaultStorm().entryPruningTailSize(2).build()), clock);
    st.put(key("e1"), "e1", 1);
    st.put(key("e2"), "e2", 1);
    st.put(key("e3"), "e3", 1);
    st.put(key("live"), "live", 1000);
    assertEquals(State.FULL, poll(st, "live", 10_000));
    StringBuilder left = new StringBuilder();
    for (String id : new String[] { "e1", "e2", "e3" }) {
      st.retainIf(key(id), value -> left.append(value) != null);
    }
    assertEquals("e3", left.toString());
  }

  @Test
  void putAndRemoveEndTheFlight() {
    StormTracker<String> st = new StormTracker<>(StormSettings.of(defaultStorm().build()), clock);
    assertEquals(State.FETCH, poll(st, "a", 10_000));
    st.remove(key("a"));
    assertEquals(State.FETCH, poll(st, "a", 10_000));
    st.put(key("b"), "b", 10);
    assertEquals(State.FETCH, poll(st, "b", 10_000));
    st.put(key("b"), "b", 10);
    assertEquals(State.FETCH, poll(st, "b", 10_000));
  }

  // retainIf changes counters without ending a flight.
  @Test
  void retainIfKeepsTheFlight() {
    StormTracker<String> st = new StormTracker<>(StormSettings.of(defaultStorm().build()), clock);
    assertEquals(State.FETCH, poll(st, "a", 10_000));
    st.retainIf(key("a"), value -> false);
    assertEquals(State.WAIT, poll(st, "a", 10_000));
    st.put(key("b"), "b", 1000);
    st.retainIf(key("b"), value -> false);
    assertEquals(State.FETCH, poll(st, "b", 10_000));
    st.put(key("c"), "c", 1000);
    st.retainIf(key("c"), value -> true);
    assertEquals(State.FULL, poll(st, "c", 10_000));
  }

  // A caller for an absent key refetches after graceInterval, which is at most inFlightTtl,
  // so only a caller waiting for a fanOut slot runs out of time.
  // Slots free up only by the once-a-second prune here, after the wait limit.
  @Test
  void waitingEndsWithThrottlingAfterInFlightTtl() throws Exception {
    StormTrackingCache settings = defaultStorm().gracePeriod(Duration.ofMillis(100)).graceInterval(Duration.ofMillis(100)).inFlightTtl(Duration.ofMillis(100)).fanOut(1).sleep(Duration.ofMillis(1)).build();
    StormTracker<String> st = new StormTracker<>(StormSettings.of(settings), clock);
    assertEquals(State.FETCH, poll(st, "b", 10_000));
    clock.set(10_050);
    Waiter waiter = new Waiter(st, "a");
    waiter.awaitParked();
    // Waiting exactly inFlightTtl is still allowed.
    clock.setMonotonic(10_150);
    TimeUnit.MILLISECONDS.sleep(50);
    assertTrue(waiter.thread.isAlive());
    clock.setMonotonic(10_151);
    waiter.thread.join(5000);
    ThrottlingException thrown = assertInstanceOf(ThrottlingException.class, waiter.result.get());
    assertEquals("Storm cache inFlightTTL exceeded.", thrown.getMessage());
    assertTrue(thrown.isRetryable());
  }

  @Test
  void interruptedWaitRestoresTheInterruptFlag() throws Exception {
    StormTracker<String> st = new StormTracker<>(StormSettings.of(defaultStorm().build()), clock);
    clock.set(10_000);
    st.get(key("a"));
    Waiter waiter = new Waiter(st, "a");
    waiter.awaitParked();
    waiter.thread.interrupt();
    waiter.thread.join(5000);
    ThrottlingException thrown = assertInstanceOf(ThrottlingException.class, waiter.result.get());
    assertEquals("Storm cache wait was interrupted.", thrown.getMessage());
    assertInstanceOf(InterruptedException.class, thrown.getCause());
    assertFalse(thrown.isRetryable());
    assertTrue(waiter.interruptedAfter.get());
  }

  // F1: a waiter wakes when the entry is put, not after its sleep (an hour here).
  @Test
  void putWakesWaiters() throws Exception {
    StormTracker<String> st = new StormTracker<>(StormSettings.of(defaultStorm().sleep(Duration.ofMillis(3_600_000)).build()), clock);
    clock.set(10_000);
    st.get(key("a"));
    Waiter waiter = new Waiter(st, "a");
    waiter.awaitParked();
    st.put(key("a"), "fetched", 1000);
    waiter.thread.join(5000);
    assertEquals("fetched", ((Lookup<?>) waiter.result.get()).value());
  }

  @Test
  void removeWakesWaitersToFetch() throws Exception {
    StormTracker<String> st = new StormTracker<>(StormSettings.of(defaultStorm().sleep(Duration.ofMillis(3_600_000)).build()), clock);
    clock.set(10_000);
    st.get(key("a"));
    Waiter waiter = new Waiter(st, "a");
    waiter.awaitParked();
    st.remove(key("a"));
    waiter.thread.join(5000);
    assertEquals(Lookup.MISSING, ((Lookup<?>) waiter.result.get()).missReason());
  }

  @Test
  void aWaiterSeesTimePassWithoutASignal() throws Exception {
    StormTracker<String> st = new StormTracker<>(StormSettings.of(defaultStorm().graceInterval(Duration.ofMillis(1000)).sleep(Duration.ofMillis(1)).build()), clock);
    clock.set(10_000);
    st.get(key("a"));
    Waiter waiter = new Waiter(st, "a");
    waiter.awaitParked();
    clock.set(11_000);
    waiter.thread.join(5000);
    assertEquals(Lookup.MISSING, ((Lookup<?>) waiter.result.get()).missReason());
  }

  private State poll(StormTracker<String> st, String id, long now) {
    clock.set(now);
    return pollAt(st, id);
  }

  private State pollAt(StormTracker<String> st, String id) {
    Waiter waiter = new Waiter(st, id);
    if (waiter.parkedOrDone()) {
      waiter.thread.interrupt();
      join(waiter.thread);
      ThrottlingException thrown = assertInstanceOf(ThrottlingException.class, waiter.result.get());
      assertInstanceOf(InterruptedException.class, thrown.getCause());
      return State.WAIT;
    }
    Lookup<?> lookup = (Lookup<?>) waiter.result.get();
    return lookup.isHit() ? State.FULL : State.FETCH;
  }

  private static void join(Thread thread) {
    try {
      thread.join(5000);
    } catch (InterruptedException e) {
      throw new IllegalStateException(e);
    }
    assertTrue(!thread.isAlive(), "the caller did not finish");
  }

  /** A get on its own thread. */
  private static final class Waiter {

    final Thread thread;
    final AtomicReference<Object> result = new AtomicReference<>();
    final AtomicBoolean interruptedAfter = new AtomicBoolean();

    Waiter(StormTracker<String> st, String id) {
      thread = new Thread(() -> {
        try {
          result.set(st.get(key(id)));
        } catch (RuntimeException e) {
          result.set(e);
        }
        interruptedAfter.set(Thread.currentThread().isInterrupted());
      });
      thread.start();
    }

    /** True once the caller parks to wait, false once it has returned. */
    boolean parkedOrDone() {
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
      while (System.nanoTime() < deadline) {
        Thread.State state = thread.getState();
        if (state == Thread.State.TIMED_WAITING) {
          return true;
        }
        if (state == Thread.State.TERMINATED) {
          return false;
        }
        Thread.yield();
      }
      throw new IllegalStateException("the caller neither waited nor finished");
    }

    void awaitParked() {
      assertTrue(parkedOrDone(), "the caller did not wait");
    }
  }
}
