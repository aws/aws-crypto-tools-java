// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal.cache;

/** A clock the test sets; wall and monotonic time move together unless set apart. */
final class TestClock implements CacheClock {

  private volatile long wall;
  private volatile long monotonic;

  TestClock(long millis) {
    set(millis);
  }

  void set(long millis) {
    wall = millis;
    monotonic = millis;
  }

  void setWall(long millis) {
    wall = millis;
  }

  void setMonotonic(long millis) {
    monotonic = millis;
  }

  @Override
  public long wallMillis() {
    return wall;
  }

  @Override
  public long monotonicMillis() {
    return monotonic;
  }
}
