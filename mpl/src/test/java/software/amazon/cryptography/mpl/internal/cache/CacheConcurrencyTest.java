// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal.cache;

import java.time.Duration;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.mpl.internal.cache.LocalCacheTest.key;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import software.amazon.cryptography.mpl.cache.CacheType;
import software.amazon.cryptography.mpl.cache.StormTrackingCache;
import software.amazon.cryptography.mpl.exceptions.ThrottlingException;

// Many threads on the thread-safe caches.
// The storm-tracking tests freeze the clock, so only puts and removes end a flight.
@Timeout(60)
class CacheConcurrencyTest {

  private static final int THREADS = 32;

  private final ExecutorService pool = Executors.newFixedThreadPool(THREADS);
  private final TestClock clock = new TestClock(10_000);

  @AfterEach
  void shutdown() {
    pool.shutdownNow();
  }

  @Test
  void multiThreadedCacheStaysConsistent() throws Exception {
    for (CacheEngine<String> cache : threadSafe(4)) {
      List<Callable<Integer>> tasks = new ArrayList<>();
      for (int t = 0; t < THREADS; t++) {
        tasks.add(() -> {
          int hits = 0;
          ThreadLocalRandom random = ThreadLocalRandom.current();
          for (int i = 0; i < 2000; i++) {
            String id = "k" + random.nextInt(8);
            switch (random.nextInt(4)) {
              case 0:
                cache.put(key(id), id + ":" + i, Long.MAX_VALUE);
                break;
              case 1:
                cache.remove(key(id));
                break;
              case 2:
                cache.retainIf(key(id), value -> value.startsWith(id + ":"));
                break;
              default:
                Lookup<String> lookup;
                try {
                  lookup = cache.get(key(id));
                } catch (ThrottlingException e) {
                  // Another caller refetched the key while this one waited, so the wait outlived inFlightTtl.
                  continue;
                }
                if (lookup.isHit()) {
                  // Never another key's value.
                  assertTrue(lookup.value().startsWith(id + ":"), lookup.value());
                  hits++;
                }
            }
          }
          return hits;
        });
      }
      int hits = 0;
      for (Future<Integer> result : pool.invokeAll(tasks)) {
        hits += result.get();
      }
      assertTrue(hits > 0);
      int present = 0;
      for (int k = 0; k < 8; k++) {
        if (cache.get(key("k" + k)).isHit()) {
          present++;
        }
      }
      assertTrue(present <= 4, "more entries than the capacity: " + present);
    }
  }

  // All callers ask for one absent key: one fetches, the others wait for its put.
  @Test
  void oneCallerFetchesAMissingEntry() throws Exception {
    StormTracker<String> st = new StormTracker<>(settings().build(), clock);
    AtomicInteger fetches = new AtomicInteger();
    List<Future<String>> results = everyone(() -> {
      Lookup<String> lookup = st.get(key("k"));
      if (lookup.isHit()) {
        return lookup.value();
      }
      fetches.incrementAndGet();
      TimeUnit.MILLISECONDS.sleep(50);
      st.put(key("k"), "fetched", 1000);
      return "fetched";
    });
    for (Future<String> result : results) {
      assertEquals("fetched", result.get(30, TimeUnit.SECONDS));
    }
    assertEquals(1, fetches.get());
  }

  // Inside the grace period: one caller refreshes, everyone else keeps using the entry.
  @Test
  void oneCallerRefreshesInsideTheGracePeriod() throws Exception {
    StormTracker<String> st = new StormTracker<>(settings().build(), clock);
    st.put(key("k"), "old", 10 + 5);
    AtomicInteger refreshes = new AtomicInteger();
    AtomicInteger olds = new AtomicInteger();
    List<Future<String>> results = everyone(() -> {
      Lookup<String> lookup = st.get(key("k"));
      if (lookup.isHit()) {
        olds.incrementAndGet();
        return lookup.value();
      }
      refreshes.incrementAndGet();
      return "refresh";
    });
    for (Future<String> result : results) {
      result.get(30, TimeUnit.SECONDS);
    }
    assertEquals(1, refreshes.get());
    assertEquals(THREADS - 1, olds.get());
  }

  // Distinct absent keys: at most fanOut fetches run at once; every caller ends with its entry.
  @Test
  void fetchesStayWithinFanOut() throws Exception {
    int fanOut = 3;
    StormTracker<String> st = new StormTracker<>(settings().fanOut(fanOut).build(), clock);
    AtomicInteger running = new AtomicInteger();
    AtomicInteger maxRunning = new AtomicInteger();
    AtomicInteger fetches = new AtomicInteger();
    AtomicInteger next = new AtomicInteger();
    List<Future<String>> results = everyone(() -> {
      String id = "k" + (next.getAndIncrement() % 12);
      while (true) {
        Lookup<String> lookup = st.get(key(id));
        if (lookup.isHit()) {
          return lookup.value();
        }
        fetches.incrementAndGet();
        int now = running.incrementAndGet();
        maxRunning.accumulateAndGet(now, Math::max);
        TimeUnit.MILLISECONDS.sleep(20);
        // Count the fetch as finished before the put frees its slot.
        running.decrementAndGet();
        st.put(key(id), id, 1000);
      }
    });
    for (Future<String> result : results) {
      assertTrue(result.get(60, TimeUnit.SECONDS).startsWith("k"));
    }
    assertTrue(maxRunning.get() <= fanOut, "concurrent fetches: " + maxRunning.get());
    assertEquals(fanOut, maxRunning.get());
    assertEquals(12, fetches.get());
  }

  private <T> List<Future<T>> everyone(Callable<T> task) throws InterruptedException {
    CountDownLatch start = new CountDownLatch(1);
    List<Future<T>> results = new ArrayList<>();
    for (int t = 0; t < THREADS; t++) {
      results.add(
        pool.submit(() -> {
          start.await();
          return task.call();
        })
      );
    }
    start.countDown();
    return results;
  }

  private List<CacheEngine<String>> threadSafe(int entryCapacity) {
    List<CacheEngine<String>> caches = new ArrayList<>();
    caches.add(Caches.engine(CacheType.multiThreaded(entryCapacity), clock));
    // On the system clock with 5 ms windows: a caller for a key nobody puts again waits at most 5 ms.
    StormTrackingCache shortWindows = settings()
      .entryCapacity(entryCapacity)
      .gracePeriod(Duration.ofMillis(5))
      .graceInterval(Duration.ofMillis(5))
      .inFlightTtl(Duration.ofMillis(5))
      .sleep(Duration.ofMillis(1))
      .build();
    caches.add(new StormTracker<>(shortWindows, CacheClock.SYSTEM));
    return caches;
  }

  // Wide grace and in-flight windows, so the frozen clock never ends a flight.
  private static StormTrackingCache.Builder settings() {
    return StormTrackingCache
      .builder()
      .entryCapacity(100)
      .gracePeriod(Duration.ofMillis(10_000))
      .graceInterval(Duration.ofMillis(10_000))
      .inFlightTtl(Duration.ofMillis(10_000))
      .fanOut(20)
      .sleep(Duration.ofMillis(5));
  }
}
