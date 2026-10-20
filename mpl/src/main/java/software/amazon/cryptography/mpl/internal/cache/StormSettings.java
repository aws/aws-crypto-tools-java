// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal.cache;

import java.util.function.Function;
import software.amazon.cryptography.mpl.cache.StormTrackingCache;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

/**
 * Storm-tracking settings as the Dafny-based MPL's StormTrackingCache holds them: counting numbers (1 to 2^31 - 1),
 * with the grace period, grace interval, and in-flight TTL in seconds or in milliseconds.
 *
 * <p>The unit changes no cache behavior: {@link StormTracker} works in milliseconds, as StormTracker.dfy does.
 * It shows only in the numbers of the inconsistent-settings message and in the hierarchical keyring's TTL check,
 * which rounds a grace period in milliseconds down to whole seconds.
 * These settings hold any configuration of the Dafny-based model, its unit included.
 * {@link StormTrackingCache} registers its conversions when it loads.
 */
public final class StormSettings {

  private static volatile Function<StormSettings, StormTrackingCache> toPublic;
  private static volatile Function<StormTrackingCache, StormSettings> fromPublic;

  public final int entryCapacity;
  public final int entryPruningTailSize;
  public final int gracePeriod;
  public final int graceInterval;
  public final int fanOut;
  public final int inFlightTtl;
  public final int sleepMilli;
  /** Whether gracePeriod, graceInterval, and inFlightTtl are in seconds; otherwise milliseconds. */
  public final boolean seconds;

  private StormSettings(
    int entryCapacity,
    int entryPruningTailSize,
    int gracePeriod,
    int graceInterval,
    int fanOut,
    int inFlightTtl,
    int sleepMilli,
    boolean seconds
  ) {
    this.entryCapacity = entryCapacity;
    this.entryPruningTailSize = entryPruningTailSize;
    this.gracePeriod = gracePeriod;
    this.graceInterval = graceInterval;
    this.fanOut = fanOut;
    this.inFlightTtl = inFlightTtl;
    this.sleepMilli = sleepMilli;
    this.seconds = seconds;
  }

  /**
   * Checks the settings as the Dafny-based MPL did, in the same order and with the same messages.
   *
   * @throws ValidationException if a number is below 1 or the times are inconsistent
   */
  public static StormSettings create(
    int entryCapacity,
    int entryPruningTailSize,
    int gracePeriod,
    int graceInterval,
    int fanOut,
    int inFlightTtl,
    int sleepMilli,
    boolean seconds
  ) {
    atLeastOne("entryCapacity", entryCapacity);
    atLeastOne("entryPruningTailSize", entryPruningTailSize);
    atLeastOne("gracePeriod", gracePeriod);
    atLeastOne("graceInterval", graceInterval);
    atLeastOne("fanOut", fanOut);
    atLeastOne("inFlightTTL", inFlightTtl);
    atLeastOne("sleepMilli", sleepMilli);
    if (!(graceInterval <= gracePeriod && inFlightTtl <= gracePeriod && graceInterval <= inFlightTtl)) {
      throw new ValidationException(
        inconsistentMessage(graceInterval <= gracePeriod, inFlightTtl <= gracePeriod, String.valueOf(gracePeriod), String.valueOf(graceInterval), String.valueOf(inFlightTtl))
      );
    }
    return new StormSettings(entryCapacity, entryPruningTailSize, gracePeriod, graceInterval, fanOut, inFlightTtl, sleepMilli, seconds);
  }

  /**
   * Text from StormTracker.dfy BadCacheMsg, with the times as given.
   * It names only the first two rules, so graceInterval &gt; inFlightTtl alone yields just the prefix.
   */
  public static String inconsistentMessage(
    boolean intervalWithinPeriod,
    boolean inFlightWithinPeriod,
    String gracePeriod,
    String graceInterval,
    String inFlightTtl
  ) {
    String message = "For a StormCache : ";
    if (!intervalWithinPeriod) {
      message +=
        "graceInterval must not exceed gracePeriod, yet configuration has graceInterval=" + graceInterval +
        " and gracePeriod=" + gracePeriod + ". ";
    }
    if (!inFlightWithinPeriod) {
      message +=
        "inFlightTTL must not exceed gracePeriod, yet configuration has inFlightTTL=" + inFlightTtl +
        " and gracePeriod=" + gracePeriod + ". ";
    }
    return message;
  }

  public static void atLeastOne(String field, long value) {
    if (value < 1) {
      throw new ValidationException("`" + field + "` must be greater than or equal to 1");
    }
  }

  public static void register(Function<StormSettings, StormTrackingCache> create, Function<StormTrackingCache, StormSettings> read) {
    toPublic = create;
    fromPublic = read;
  }

  /** The settings of {@code cache}. */
  public static StormSettings of(StormTrackingCache cache) {
    return fromPublic.apply(cache);
  }

  /** The public settings holding exactly these values. */
  public StormTrackingCache toPublic() {
    load();
    return toPublic.apply(this);
  }

  public long gracePeriodMillis() {
    return millis(gracePeriod);
  }

  public long graceIntervalMillis() {
    return millis(graceInterval);
  }

  public long inFlightTtlMillis() {
    return millis(inFlightTtl);
  }

  /** The grace period in whole seconds, rounded down, as CheckCache in AwsCryptographyMaterialProvidersOperations.dfy computes it. */
  public long gracePeriodSeconds() {
    return seconds ? gracePeriod : gracePeriod / 1000;
  }

  private long millis(int time) {
    return seconds ? time * 1000L : time;
  }

  private static void load() {
    try {
      Class.forName(StormTrackingCache.class.getName(), true, StormTrackingCache.class.getClassLoader());
    } catch (ClassNotFoundException e) {
      throw new IllegalStateException(e);
    }
  }
}
