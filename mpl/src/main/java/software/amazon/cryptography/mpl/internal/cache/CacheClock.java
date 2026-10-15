// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal.cache;

import java.util.concurrent.TimeUnit;

/**
 * The time sources of the built-in caches; tests substitute their own.
 * Entry expiry is an absolute instant, so it is compared with wall-clock time.
 * Durations (how long a refresh has been in flight, how long a caller has waited) use the monotonic clock,
 * so a wall-clock adjustment cannot stall or skip them.
 */
public interface CacheClock {
  CacheClock SYSTEM = new CacheClock() {
    @Override
    public long wallMillis() {
      return System.currentTimeMillis();
    }

    @Override
    public long monotonicMillis() {
      return TimeUnit.NANOSECONDS.toMillis(System.nanoTime());
    }
  };

  /** Milliseconds since the epoch. */
  long wallMillis();

  /** Milliseconds from an arbitrary origin, never decreasing. */
  long monotonicMillis();
}
