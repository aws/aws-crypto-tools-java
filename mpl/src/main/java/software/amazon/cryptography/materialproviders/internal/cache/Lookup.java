// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.cache;

/** The result of a cache read: the entry, or why there is none. */
public final class Lookup<V> {

  // Miss reasons as the Dafny-based caches report them (LocalCMC.dfy, StormTrackingCMC.java).
  static final String MISSING = "Entry does not exist";
  static final String EXPIRED = "Entry past TTL";

  private final V value;
  private final long expirySeconds;
  private final String missReason;

  private Lookup(V value, long expirySeconds, String missReason) {
    this.value = value;
    this.expirySeconds = expirySeconds;
    this.missReason = missReason;
  }

  static <V> Lookup<V> hit(V value, long expirySeconds) {
    return new Lookup<>(value, expirySeconds, null);
  }

  static <V> Lookup<V> miss(String reason) {
    return new Lookup<>(null, 0, reason);
  }

  public boolean isHit() {
    return missReason == null;
  }

  /** The entry; null on a miss. */
  public V value() {
    return value;
  }

  long expirySeconds() {
    return expirySeconds;
  }

  /** The Dafny-based MPL's {@code EntryDoesNotExist} message for this miss; null on a hit. */
  public String missReason() {
    return missReason;
  }
}
