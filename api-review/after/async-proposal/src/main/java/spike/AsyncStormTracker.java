package spike;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import software.amazon.cryptography.materialproviders.exceptions.ThrottlingException;

/**
 * The storm-tracking decision logic of internal/cache/StormTracker.java, unchanged, with the blocking
 * {@code lock.wait(sleepMilli)} replaced by a parked future.
 *
 * <p>{@code get} returns at once with a future of: the entry (hit), empty (a miss: this caller must
 * fetch and put), or a ThrottlingException (waited longer than inFlightTtl). A caller that must wait
 * holds no thread: its future is re-evaluated when the key is put or removed, or every sleepMilli on a
 * shared scheduler, exactly when the sync version's waiter would wake. Same grace period, grace
 * interval, fan-out, and in-flight TTL rules; same outcomes in the same order.
 *
 * <p>Waiters are completed on {@code completionExecutor}, not on the putter's thread: the putter is
 * usually an SDK response thread, and a waiter's next stage (unwrap a data key) is CPU work.
 * Simplified for the spike: a HashMap instead of the LRU LocalCache; no fan-out pruning throttle.
 */
public final class AsyncStormTracker<K, V> {
  private static final class Entry<V> {
    final V value;
    final long expiryMillis;

    Entry(V value, long expiryMillis) {
      this.value = value;
      this.expiryMillis = expiryMillis;
    }
  }

  private final class Waiter {
    final K key;
    final long waitUntil;
    final CompletableFuture<Optional<V>> future = new CompletableFuture<>();

    Waiter(K key, long waitUntil) {
      this.key = key;
      this.waitUntil = waitUntil;
    }
  }

  private final Object lock = new Object();
  private final Map<K, Entry<V>> entries = new HashMap<>();
  private final Map<K, Long> inFlight = new HashMap<>();
  private final List<Waiter> waiters = new ArrayList<>();
  private final long gracePeriod;
  private final long graceInterval;
  private final long inFlightTtl;
  private final long sleepMilli;
  private final int fanOut;
  private final LongSupplier clock;
  private final ScheduledExecutorService scheduler;
  private final Executor completionExecutor;

  public AsyncStormTracker(long gracePeriod, long graceInterval, long inFlightTtl, long sleepMilli, int fanOut,
      LongSupplier clock, ScheduledExecutorService scheduler, Executor completionExecutor) {
    this.gracePeriod = gracePeriod;
    this.graceInterval = graceInterval;
    this.inFlightTtl = inFlightTtl;
    this.sleepMilli = sleepMilli;
    this.fanOut = fanOut;
    this.clock = clock;
    this.scheduler = scheduler;
    this.completionExecutor = completionExecutor;
  }

  public CompletableFuture<Optional<V>> get(K key) {
    long waitUntil = clock.getAsLong() + inFlightTtl;
    synchronized (lock) {
      Optional<Optional<V>> decided = decide(key, waitUntil);
      if (decided.isPresent()) {
        return CompletableFuture.completedFuture(decided.get());
      }
      Waiter w = new Waiter(key, waitUntil);
      waiters.add(w);
      scheduleRecheck(w);
      return w.future;
    }
  }

  public void put(K key, V value, long expiryMillis) {
    List<Runnable> completions;
    synchronized (lock) {
      inFlight.remove(key);
      entries.put(key, new Entry<>(value, expiryMillis));
      completions = recheck(key);
    }
    completions.forEach(completionExecutor::execute); // outside the lock
  }

  public void remove(K key) {
    List<Runnable> completions;
    synchronized (lock) {
      inFlight.remove(key);
      entries.remove(key);
      completions = recheck(key);
    }
    completions.forEach(completionExecutor::execute);
  }

  // One pass of the sync loop body. Empty means "wait".
  private Optional<Optional<V>> decide(K key, long waitUntil) {
    long now = clock.getAsLong();
    Entry<V> e = entries.get(key);
    if (e != null && e.expiryMillis > now) {
      return Optional.of(refreshDue(key, e.expiryMillis, now) ? Optional.<V>empty() : Optional.of(e.value));
    }
    if (fetchDue(key, now)) {
      return Optional.of(Optional.<V>empty());
    }
    if (now > waitUntil) {
      throw new ThrottlingException("Storm cache inFlightTTL exceeded.");
    }
    return Optional.empty();
  }

  private void scheduleRecheck(Waiter w) {
    scheduler.schedule(() -> {
      List<Runnable> completions;
      synchronized (lock) {
        completions = recheck(w.key);
      }
      completions.forEach(completionExecutor::execute);
    }, sleepMilli, TimeUnit.MILLISECONDS);
  }

  // Re-runs the decision for waiters on key; returns the completions to run outside the lock.
  private List<Runnable> recheck(K key) {
    List<Runnable> out = new ArrayList<>();
    for (Waiter w : new ArrayList<>(waiters)) {
      if (!w.key.equals(key) || w.future.isDone()) {
        continue;
      }
      try {
        Optional<Optional<V>> decided = decide(key, w.waitUntil);
        if (decided.isPresent()) {
          waiters.remove(w);
          Optional<V> result = decided.get();
          out.add(() -> w.future.complete(result));
        } else {
          scheduleRecheck(w);
        }
      } catch (RuntimeException ex) {
        waiters.remove(w);
        out.add(() -> w.future.completeExceptionally(ex));
      }
    }
    return out;
  }

  private boolean refreshDue(K key, long expiry, long now) {
    if (fanOut <= inFlight.size() || expiry - gracePeriod > now) {
      return false;
    }
    Long since = inFlight.get(key);
    if (since != null && since + graceInterval > now) {
      return false;
    }
    inFlight.put(key, now);
    return true;
  }

  private boolean fetchDue(K key, long now) {
    if (fanOut <= inFlight.size()) {
      return false;
    }
    Long since = inFlight.get(key);
    if (since != null && now < since + graceInterval) {
      return false;
    }
    inFlight.put(key, now);
    return true;
  }
}
