// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.cache;

import java.util.Objects;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

/**
 * Settings for a storm-tracking cache: as an entry nears expiry, one caller at a time refreshes it while
 * others keep using it. Times are in {@link #timeUnits()} units. Immutable.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/storm-tracking-cryptographic-materials-cache.md">storm tracking cryptographic materials cache</a>.
 */
public final class StormTrackingCache {

  public static final int DEFAULT_ENTRY_PRUNING_TAIL_SIZE = 1;
  public static final int DEFAULT_GRACE_PERIOD = 10;
  public static final int DEFAULT_GRACE_INTERVAL = 1;
  public static final int DEFAULT_FAN_OUT = 20;
  public static final int DEFAULT_IN_FLIGHT_TTL = 10;
  public static final int DEFAULT_SLEEP_MILLI = 20;
  public static final TimeUnits DEFAULT_TIME_UNITS = TimeUnits.SECONDS;

  private final int entryCapacity;
  private final int entryPruningTailSize;
  private final int gracePeriod;
  private final int graceInterval;
  private final int fanOut;
  private final int inFlightTtl;
  private final int sleepMilli;
  private final TimeUnits timeUnits;

  private StormTrackingCache(Builder builder) {
    this.entryCapacity = builder.entryCapacity;
    this.entryPruningTailSize = builder.entryPruningTailSize;
    this.gracePeriod = builder.gracePeriod;
    this.graceInterval = builder.graceInterval;
    this.fanOut = builder.fanOut;
    this.inFlightTtl = builder.inFlightTtl;
    this.sleepMilli = builder.sleepMilli;
    this.timeUnits = builder.timeUnits;
  }

  public static Builder builder() {
    return new Builder();
  }

  public int entryCapacity() {
    return entryCapacity;
  }

  public int entryPruningTailSize() {
    return entryPruningTailSize;
  }

  public int gracePeriod() {
    return gracePeriod;
  }

  public int graceInterval() {
    return graceInterval;
  }

  public int fanOut() {
    return fanOut;
  }

  public int inFlightTtl() {
    return inFlightTtl;
  }

  public int sleepMilli() {
    return sleepMilli;
  }

  public TimeUnits timeUnits() {
    return timeUnits;
  }

  @Override
  public boolean equals(Object other) {
    if (!(other instanceof StormTrackingCache)) {
      return false;
    }
    StormTrackingCache that = (StormTrackingCache) other;
    return (
      entryCapacity == that.entryCapacity &&
      entryPruningTailSize == that.entryPruningTailSize &&
      gracePeriod == that.gracePeriod &&
      graceInterval == that.graceInterval &&
      fanOut == that.fanOut &&
      inFlightTtl == that.inFlightTtl &&
      sleepMilli == that.sleepMilli &&
      timeUnits == that.timeUnits
    );
  }

  @Override
  public int hashCode() {
    return Objects.hash(entryCapacity, entryPruningTailSize, gracePeriod, graceInterval, fanOut, inFlightTtl, sleepMilli, timeUnits);
  }

  @Override
  public String toString() {
    return (
      "StormTrackingCache[entryCapacity=" + entryCapacity + ", entryPruningTailSize=" + entryPruningTailSize +
      ", gracePeriod=" + gracePeriod + ", graceInterval=" + graceInterval + ", fanOut=" + fanOut +
      ", inFlightTtl=" + inFlightTtl + ", sleepMilli=" + sleepMilli + ", timeUnits=" + timeUnits + "]"
    );
  }

  /**
   * Not thread-safe. Requires {@code entryCapacity}; the rest default to the {@code DEFAULT_} constants.
   * Every number must be at least 1.
   * {@link #build()} checks graceInterval &lt;= gracePeriod, inFlightTtl &lt;= gracePeriod, and graceInterval &lt;= inFlightTtl.
   */
  public static final class Builder {

    private Integer entryCapacity;
    private int entryPruningTailSize = DEFAULT_ENTRY_PRUNING_TAIL_SIZE;
    private int gracePeriod = DEFAULT_GRACE_PERIOD;
    private int graceInterval = DEFAULT_GRACE_INTERVAL;
    private int fanOut = DEFAULT_FAN_OUT;
    private int inFlightTtl = DEFAULT_IN_FLIGHT_TTL;
    private int sleepMilli = DEFAULT_SLEEP_MILLI;
    private TimeUnits timeUnits = DEFAULT_TIME_UNITS;

    private Builder() {}

    public Builder entryCapacity(int entryCapacity) {
      this.entryCapacity = entryCapacity;
      return this;
    }

    /** Expired entries removed per prune pass. */
    public Builder entryPruningTailSize(int entryPruningTailSize) {
      this.entryPruningTailSize = entryPruningTailSize;
      return this;
    }

    /** How long before expiry refreshing starts. */
    public Builder gracePeriod(int gracePeriod) {
      this.gracePeriod = gracePeriod;
      return this;
    }

    /** How often, within the grace period, another refresh may start. */
    public Builder graceInterval(int graceInterval) {
      this.graceInterval = graceInterval;
      return this;
    }

    /** At most this many refreshes in flight at once. */
    public Builder fanOut(int fanOut) {
      this.fanOut = fanOut;
      return this;
    }

    /** How long a refresh may take before another caller may start one. */
    public Builder inFlightTtl(int inFlightTtl) {
      this.inFlightTtl = inFlightTtl;
      return this;
    }

    /** How long a waiting caller sleeps between checks, in milliseconds. */
    public Builder sleepMilli(int sleepMilli) {
      this.sleepMilli = sleepMilli;
      return this;
    }

    /**
     * The unit of {@code gracePeriod}, {@code graceInterval}, and {@code inFlightTtl}; default {@link TimeUnits#SECONDS}.
     * {@link CacheType#defaultCache} uses {@link TimeUnits#MILLISECONDS}, so copying its numbers here without its unit
     * makes every period 1000 times longer. With milliseconds a hierarchical keyring checks its TTL against the grace period
     * in whole seconds, rounded down.
     */
    public Builder timeUnits(TimeUnits timeUnits) {
      this.timeUnits = Objects.requireNonNull(timeUnits, "timeUnits");
      return this;
    }

    /** @throws ValidationException if a number is below 1 or the times are inconsistent */
    public StormTrackingCache build() {
      if (entryCapacity == null) {
        throw new ValidationException("Missing value for required field `entryCapacity`");
      }
      atLeastOne("entryCapacity", entryCapacity);
      atLeastOne("entryPruningTailSize", entryPruningTailSize);
      atLeastOne("gracePeriod", gracePeriod);
      atLeastOne("graceInterval", graceInterval);
      atLeastOne("fanOut", fanOut);
      atLeastOne("inFlightTTL", inFlightTtl);
      atLeastOne("sleepMilli", sleepMilli);
      if (!(graceInterval <= gracePeriod && inFlightTtl <= gracePeriod && graceInterval <= inFlightTtl)) {
        throw new ValidationException(inconsistentMessage());
      }
      return new StormTrackingCache(this);
    }

    // Text from StormTracker.dfy BadCacheMsg. It names only the first two rules,
    // so graceInterval > inFlightTtl alone yields just the prefix.
    private String inconsistentMessage() {
      String message = "For a StormCache : ";
      if (!(graceInterval <= gracePeriod)) {
        message +=
          "graceInterval must not exceed gracePeriod, yet configuration has graceInterval=" + graceInterval +
          " and gracePeriod=" + gracePeriod + ". ";
      }
      if (!(inFlightTtl <= gracePeriod)) {
        message +=
          "inFlightTTL must not exceed gracePeriod, yet configuration has inFlightTTL=" + inFlightTtl +
          " and gracePeriod=" + gracePeriod + ". ";
      }
      return message;
    }
  }

  static void atLeastOne(String field, int value) {
    if (value < 1) {
      throw new ValidationException("`" + field + "` must be greater than or equal to 1");
    }
  }
}
