// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.cache;

import java.time.Duration;
import java.util.Objects;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.cache.StormSettings;

/**
 * Settings for a storm-tracking cache: as an entry nears expiry, one caller at a time refreshes it while
 * others keep using it. Immutable.
 *
 * <p>The cache counts the grace period, grace interval, and in-flight TTL in milliseconds,
 * and entry expiry in whole seconds.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/storm-tracking-cryptographic-materials-cache.md">storm tracking cryptographic materials cache</a>.
 */
public final class StormTrackingCache {

  public static final int DEFAULT_ENTRY_PRUNING_TAIL_SIZE = 1;
  public static final Duration DEFAULT_GRACE_PERIOD = Duration.ofSeconds(10);
  public static final Duration DEFAULT_GRACE_INTERVAL = Duration.ofSeconds(1);
  public static final int DEFAULT_FAN_OUT = 20;
  public static final Duration DEFAULT_IN_FLIGHT_TTL = Duration.ofSeconds(10);
  public static final Duration DEFAULT_SLEEP = Duration.ofMillis(20);

  // The largest count the Dafny-based settings hold (a CountingNumber), as seconds and as milliseconds.
  private static final Duration MAX_IN_SECONDS = Duration.ofSeconds(Integer.MAX_VALUE);
  private static final Duration MAX_IN_MILLIS = Duration.ofMillis(Integer.MAX_VALUE);

  static {
    StormSettings.register(StormTrackingCache::new, cache -> cache.settings);
  }

  private final StormSettings settings;

  private StormTrackingCache(StormSettings settings) {
    this.settings = settings;
  }

  public static Builder builder() {
    return new Builder();
  }

  public int entryCapacity() {
    return settings.entryCapacity;
  }

  public int entryPruningTailSize() {
    return settings.entryPruningTailSize;
  }

  public Duration gracePeriod() {
    return Duration.ofMillis(settings.gracePeriodMillis());
  }

  public Duration graceInterval() {
    return Duration.ofMillis(settings.graceIntervalMillis());
  }

  public int fanOut() {
    return settings.fanOut;
  }

  public Duration inFlightTtl() {
    return Duration.ofMillis(settings.inFlightTtlMillis());
  }

  public Duration sleep() {
    return Duration.ofMillis(settings.sleepMilli);
  }

  @Override
  public boolean equals(Object other) {
    if (!(other instanceof StormTrackingCache)) {
      return false;
    }
    StormTrackingCache that = (StormTrackingCache) other;
    return (
      entryCapacity() == that.entryCapacity() &&
      entryPruningTailSize() == that.entryPruningTailSize() &&
      gracePeriod().equals(that.gracePeriod()) &&
      graceInterval().equals(that.graceInterval()) &&
      fanOut() == that.fanOut() &&
      inFlightTtl().equals(that.inFlightTtl()) &&
      sleep().equals(that.sleep())
    );
  }

  @Override
  public int hashCode() {
    return Objects.hash(entryCapacity(), entryPruningTailSize(), gracePeriod(), graceInterval(), fanOut(), inFlightTtl(), sleep());
  }

  @Override
  public String toString() {
    return (
      "StormTrackingCache[entryCapacity=" + entryCapacity() + ", entryPruningTailSize=" + entryPruningTailSize() +
      ", gracePeriod=" + gracePeriod() + ", graceInterval=" + graceInterval() + ", fanOut=" + fanOut() +
      ", inFlightTtl=" + inFlightTtl() + ", sleep=" + sleep() + "]"
    );
  }

  /**
   * Not thread-safe. Requires {@code entryCapacity}; the rest default to the {@code DEFAULT_} constants.
   *
   * <p>{@link #build()} throws {@link ValidationException} unless:
   * <ul>
   *   <li>every count is at least 1, and every time is positive and a whole number of milliseconds;
   *   <li>graceInterval &lt;= gracePeriod, inFlightTtl &lt;= gracePeriod, and graceInterval &lt;= inFlightTtl;
   *   <li>gracePeriod, graceInterval, and inFlightTtl are either all whole seconds of at most
   *       {@link Integer#MAX_VALUE} seconds, or all at most {@link Integer#MAX_VALUE} milliseconds;
   *   <li>sleep is at most {@link Integer#MAX_VALUE} milliseconds.
   * </ul>
   * These are the values the Dafny-based MPL's {@code StormTrackingCache} can hold.
   * Times that are all whole seconds are held as its {@code Seconds} time unit, any others as {@code Milliseconds};
   * the cache behaves the same either way.
   */
  public static final class Builder {

    private Integer entryCapacity;
    private int entryPruningTailSize = DEFAULT_ENTRY_PRUNING_TAIL_SIZE;
    private Duration gracePeriod = DEFAULT_GRACE_PERIOD;
    private Duration graceInterval = DEFAULT_GRACE_INTERVAL;
    private int fanOut = DEFAULT_FAN_OUT;
    private Duration inFlightTtl = DEFAULT_IN_FLIGHT_TTL;
    private Duration sleep = DEFAULT_SLEEP;

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
    public Builder gracePeriod(Duration gracePeriod) {
      this.gracePeriod = Objects.requireNonNull(gracePeriod, "gracePeriod");
      return this;
    }

    /** How often, within the grace period, another refresh may start. */
    public Builder graceInterval(Duration graceInterval) {
      this.graceInterval = Objects.requireNonNull(graceInterval, "graceInterval");
      return this;
    }

    /** At most this many refreshes in flight at once. */
    public Builder fanOut(int fanOut) {
      this.fanOut = fanOut;
      return this;
    }

    /** How long a refresh may take before another caller may start one. */
    public Builder inFlightTtl(Duration inFlightTtl) {
      this.inFlightTtl = Objects.requireNonNull(inFlightTtl, "inFlightTtl");
      return this;
    }

    /** How long a waiting caller sleeps between checks. */
    public Builder sleep(Duration sleep) {
      this.sleep = Objects.requireNonNull(sleep, "sleep");
      return this;
    }

    /** @throws ValidationException for the settings listed on {@link Builder} */
    public StormTrackingCache build() {
      if (entryCapacity == null) {
        throw new ValidationException("Missing value for required field `entryCapacity`");
      }
      StormSettings.atLeastOne("entryCapacity", entryCapacity);
      StormSettings.atLeastOne("entryPruningTailSize", entryPruningTailSize);
      long gracePeriodMillis = millis("gracePeriod", gracePeriod);
      long graceIntervalMillis = millis("graceInterval", graceInterval);
      StormSettings.atLeastOne("fanOut", fanOut);
      long inFlightTtlMillis = millis("inFlightTtl", inFlightTtl);
      long sleepMillis = millis("sleep", sleep);
      boolean intervalWithinPeriod = graceInterval.compareTo(gracePeriod) <= 0;
      boolean inFlightWithinPeriod = inFlightTtl.compareTo(gracePeriod) <= 0;
      if (!(intervalWithinPeriod && inFlightWithinPeriod && graceInterval.compareTo(inFlightTtl) <= 0)) {
        throw new ValidationException(
          StormSettings.inconsistentMessage(intervalWithinPeriod, inFlightWithinPeriod, gracePeriod.toString(), graceInterval.toString(), inFlightTtl.toString())
        );
      }
      if (sleep.compareTo(MAX_IN_MILLIS) > 0) {
        throw new ValidationException("`sleep` must be at most " + Integer.MAX_VALUE + " milliseconds");
      }
      boolean seconds = gracePeriodMillis % 1000 == 0 && graceIntervalMillis % 1000 == 0 && inFlightTtlMillis % 1000 == 0;
      Duration max = seconds ? MAX_IN_SECONDS : MAX_IN_MILLIS;
      if (gracePeriod.compareTo(max) > 0 || graceInterval.compareTo(max) > 0 || inFlightTtl.compareTo(max) > 0) {
        throw new ValidationException(
          "gracePeriod, graceInterval, and inFlightTtl must be whole seconds of at most " + Integer.MAX_VALUE +
          " seconds, or at most " + Integer.MAX_VALUE + " milliseconds; they are " + gracePeriod + ", " + graceInterval +
          ", and " + inFlightTtl
        );
      }
      long unit = seconds ? 1000 : 1;
      return new StormTrackingCache(
        StormSettings.create(
          entryCapacity,
          entryPruningTailSize,
          (int) (gracePeriodMillis / unit),
          (int) (graceIntervalMillis / unit),
          fanOut,
          (int) (inFlightTtlMillis / unit),
          (int) sleepMillis,
          seconds
        )
      );
    }

    // Positive whole milliseconds. A time too long for either unit, which Duration.toMillis may not convert,
    // is Long.MAX_VALUE: not whole seconds, and the range checks in build() reject it.
    private static long millis(String field, Duration time) {
      if (time.isNegative() || time.isZero()) {
        throw new ValidationException("`" + field + "` must be positive");
      }
      if (time.getNano() % 1_000_000 != 0) {
        throw new ValidationException("`" + field + "` must be a whole number of milliseconds");
      }
      return time.compareTo(MAX_IN_SECONDS) > 0 ? Long.MAX_VALUE : time.toMillis();
    }
  }
}
