// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.cache;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.keystore.BeaconKeyMaterials;
import software.amazon.cryptography.keystore.BranchKeyMaterials;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.exceptions.ThrottlingException;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.internal.KeyMaterialsAccess;
import software.amazon.cryptography.materialproviders.internal.cache.BuiltInCache;
import software.amazon.cryptography.materialproviders.internal.cache.CacheClock;
import software.amazon.cryptography.materialproviders.internal.cache.Caches;
import software.amazon.cryptography.materialproviders.internal.cache.StormSettings;

// The public cache API: the built-in caches' builders and settings, keys, and entries.
class CacheApiTest {

  @Test
  void builtInCacheSettings() {
    SingleThreadedCache single = SingleThreadedCache.builder().entryCapacity(7).build();
    assertEquals(Arrays.asList(7, 1), Arrays.asList(single.entryCapacity(), single.entryPruningTailSize()));
    MultiThreadedCache multi = MultiThreadedCache.builder().entryCapacity(8).entryPruningTailSize(3).build();
    assertEquals(Arrays.asList(8, 3), Arrays.asList(multi.entryCapacity(), multi.entryPruningTailSize()));
    assertEquals(3, SingleThreadedCache.builder().entryCapacity(8).entryPruningTailSize(3).build().entryPruningTailSize());
    assertEquals(1, MultiThreadedCache.builder().entryCapacity(8).build().entryPruningTailSize());
    assertEquals(9, DefaultCache.builder().entryCapacity(9).build().entryCapacity());
    assertEquals("SingleThreadedCache[entryCapacity=7, entryPruningTailSize=1]", single.toString());
    assertEquals("MultiThreadedCache[entryCapacity=8, entryPruningTailSize=3]", multi.toString());
    assertEquals("DefaultCache[entryCapacity=9]", DefaultCache.builder().entryCapacity(9).build().toString());
    assertEquals("NoCache", NoCache.create().toString());
    // StormTracker.dfy DefaultStorm, in milliseconds. The storm-tracking builder's defaults are the same times, held in seconds.
    StormSettings dafnyDefault = Caches.defaultSettings(9);
    assertEquals(
      Arrays.asList(9, 1, 10_000, 1000, 20, 10_000, 20),
      Arrays.asList(
        dafnyDefault.entryCapacity,
        dafnyDefault.entryPruningTailSize,
        dafnyDefault.gracePeriod,
        dafnyDefault.graceInterval,
        dafnyDefault.fanOut,
        dafnyDefault.inFlightTtl,
        dafnyDefault.sleepMilli
      )
    );
    assertFalse(dafnyDefault.seconds);
    assertEquals(settingsOf(dafnyDefault.toPublic()), settingsOf(StormTrackingCache.builder().entryCapacity(9).build()));
    assertTrue(StormSettings.of(StormTrackingCache.builder().entryCapacity(9).build()).seconds);
  }

  @Test
  void builtInCacheValidation() {
    List<Supplier<CryptographicMaterialsCache>> invalidCapacity = Arrays.asList(
      () -> DefaultCache.builder().entryCapacity(0).build(),
      () -> DefaultCache.builder().entryCapacity(-1).build(),
      () -> SingleThreadedCache.builder().entryCapacity(0).build(),
      () -> SingleThreadedCache.builder().entryCapacity(0).entryPruningTailSize(1).build(),
      () -> MultiThreadedCache.builder().entryCapacity(0).build(),
      () -> MultiThreadedCache.builder().entryCapacity(Integer.MIN_VALUE).entryPruningTailSize(1).build()
    );
    for (Supplier<CryptographicMaterialsCache> create : invalidCapacity) {
      assertEquals("`entryCapacity` must be greater than or equal to 1", assertThrows(ValidationException.class, create::get).getMessage());
    }
    for (Supplier<CryptographicMaterialsCache> create : Arrays.<Supplier<CryptographicMaterialsCache>>asList(
      () -> SingleThreadedCache.builder().entryCapacity(1).entryPruningTailSize(0).build(),
      () -> MultiThreadedCache.builder().entryCapacity(1).entryPruningTailSize(-1).build()
    )) {
      assertEquals(
        "`entryPruningTailSize` must be greater than or equal to 1",
        assertThrows(ValidationException.class, create::get).getMessage()
      );
    }
    for (Supplier<CryptographicMaterialsCache> create : Arrays.<Supplier<CryptographicMaterialsCache>>asList(
      () -> DefaultCache.builder().build(),
      () -> SingleThreadedCache.builder().build(),
      () -> MultiThreadedCache.builder().entryPruningTailSize(2).build(),
      () -> StormTrackingCache.builder().build()
    )) {
      assertEquals("Missing value for required field `entryCapacity`", assertThrows(ValidationException.class, create::get).getMessage());
    }
  }

  // Every setting, the times in milliseconds.
  private static List<Object> settingsOf(StormTrackingCache cache) {
    return Arrays.<Object>asList(
      cache.entryCapacity(),
      cache.entryPruningTailSize(),
      cache.gracePeriod(),
      cache.graceInterval(),
      cache.fanOut(),
      cache.inFlightTtl(),
      cache.sleep()
    );
  }

  @Test
  void stormTrackingDefaults() {
    StormTrackingCache settings = StormTrackingCache.builder().entryCapacity(5).build();
    assertEquals(5, settings.entryCapacity());
    assertEquals(StormTrackingCache.DEFAULT_ENTRY_PRUNING_TAIL_SIZE, settings.entryPruningTailSize());
    assertEquals(StormTrackingCache.DEFAULT_GRACE_PERIOD, settings.gracePeriod());
    assertEquals(StormTrackingCache.DEFAULT_GRACE_INTERVAL, settings.graceInterval());
    assertEquals(StormTrackingCache.DEFAULT_FAN_OUT, settings.fanOut());
    assertEquals(StormTrackingCache.DEFAULT_IN_FLIGHT_TTL, settings.inFlightTtl());
    assertEquals(StormTrackingCache.DEFAULT_SLEEP, settings.sleep());
    // StormTracker.dfy DefaultStorm.
    assertEquals(
      Arrays.<Object>asList(1, Duration.ofSeconds(10), Duration.ofSeconds(1), 20, Duration.ofSeconds(10), Duration.ofMillis(20)),
      Arrays.<Object>asList(
        StormTrackingCache.DEFAULT_ENTRY_PRUNING_TAIL_SIZE,
        StormTrackingCache.DEFAULT_GRACE_PERIOD,
        StormTrackingCache.DEFAULT_GRACE_INTERVAL,
        StormTrackingCache.DEFAULT_FAN_OUT,
        StormTrackingCache.DEFAULT_IN_FLIGHT_TTL,
        StormTrackingCache.DEFAULT_SLEEP
      )
    );
  }

  @Test
  void stormTrackingSetters() {
    StormTrackingCache settings = storm(2, 3, 9, 4, 6, 7, 8);
    assertEquals(
      Arrays.<Object>asList(2, 3, Duration.ofMillis(9), Duration.ofMillis(4), 6, Duration.ofMillis(7), Duration.ofMillis(8)),
      Arrays.<Object>asList(
        settings.entryCapacity(),
        settings.entryPruningTailSize(),
        settings.gracePeriod(),
        settings.graceInterval(),
        settings.fanOut(),
        settings.inFlightTtl(),
        settings.sleep()
      )
    );
    assertEquals(
      "StormTrackingCache[entryCapacity=2, entryPruningTailSize=3, gracePeriod=PT0.009S, graceInterval=PT0.004S, fanOut=6, " +
      "inFlightTtl=PT0.007S, sleep=PT0.008S]",
      settings.toString()
    );
    // Equal times give equal settings whichever unit holds them.
    assertEquals(settingsOf(StormSettings.create(2, 3, 9000, 4000, 6, 7000, 8, false).toPublic()), settingsOf(StormSettings.create(2, 3, 9, 4, 6, 7, 8, true).toPublic()));
  }

  // Times in milliseconds.
  private static StormTrackingCache storm(int capacity, int tail, long gracePeriod, long graceInterval, int fanOut, long inFlightTtl, long sleep) {
    return StormTrackingCache
      .builder()
      .entryCapacity(capacity)
      .entryPruningTailSize(tail)
      .gracePeriod(Duration.ofMillis(gracePeriod))
      .graceInterval(Duration.ofMillis(graceInterval))
      .fanOut(fanOut)
      .inFlightTtl(Duration.ofMillis(inFlightTtl))
      .sleep(Duration.ofMillis(sleep))
      .build();
  }

  // The Dafny-based settings' checks, which the test adapter reaches for every old configuration.
  @Test
  void stormSettingsValidation() {
    String[] fields = { "entryCapacity", "entryPruningTailSize", "gracePeriod", "graceInterval", "fanOut", "inFlightTTL", "sleepMilli" };
    for (int field = 0; field < fields.length; field++) {
      for (int value : new int[] { 0, -1 }) {
        int[] numbers = { 1, 1, 10, 1, 1, 10, 1 };
        numbers[field] = value;
        if (field == 2) {
          numbers[3] = numbers[5] = value;
        }
        assertEquals(
          "`" + fields[field] + "` must be greater than or equal to 1",
          assertThrows(
            ValidationException.class,
            () -> StormSettings.create(numbers[0], numbers[1], numbers[2], numbers[3], numbers[4], numbers[5], numbers[6], true)
          ).getMessage()
        );
      }
    }
    // The consistency rules and StormTracker.dfy BadCacheMsg.
    assertEquals(
      "For a StormCache : graceInterval must not exceed gracePeriod, yet configuration has graceInterval=11 and gracePeriod=10. ",
      inconsistent(10, 11, 10)
    );
    assertEquals(
      "For a StormCache : inFlightTTL must not exceed gracePeriod, yet configuration has inFlightTTL=11 and gracePeriod=10. ",
      inconsistent(10, 1, 11)
    );
    assertEquals(
      "For a StormCache : graceInterval must not exceed gracePeriod, yet configuration has graceInterval=12 and gracePeriod=10. " +
      "inFlightTTL must not exceed gracePeriod, yet configuration has inFlightTTL=11 and gracePeriod=10. ",
      inconsistent(10, 12, 11)
    );
    assertEquals("For a StormCache : ", inconsistent(10, 3, 2));
    // Equal values are consistent.
    StormSettings.create(1, 1, 5, 5, 1, 5, 1, true);
    // The hierarchical keyring's TTL check rounds a grace period in milliseconds down to seconds.
    assertEquals(5, StormSettings.create(1, 1, 5999, 1, 1, 1, 1, false).gracePeriodSeconds());
    assertEquals(5, StormSettings.create(1, 1, 5, 1, 1, 1, 1, true).gracePeriodSeconds());
  }

  private static String inconsistent(int gracePeriod, int graceInterval, int inFlightTtl) {
    return assertThrows(ValidationException.class, () -> StormSettings.create(1, 1, gracePeriod, graceInterval, 1, inFlightTtl, 1, true)).getMessage();
  }

  @Test
  void stormTrackingBuilderValidation() {
    assertEquals(
      "Missing value for required field `entryCapacity`",
      assertThrows(ValidationException.class, () -> StormTrackingCache.builder().build()).getMessage()
    );
    assertEquals(
      "`fanOut` must be greater than or equal to 1",
      assertThrows(ValidationException.class, () -> StormTrackingCache.builder().entryCapacity(1).fanOut(0).build()).getMessage()
    );
    String[] times = { "gracePeriod", "graceInterval", "inFlightTtl", "sleep" };
    for (String field : times) {
      for (Duration time : Arrays.asList(Duration.ZERO, Duration.ofMillis(-1))) {
        assertEquals("`" + field + "` must be positive", assertThrows(ValidationException.class, () -> withTime(field, time)).getMessage());
      }
      assertEquals(
        "`" + field + "` must be a whole number of milliseconds",
        assertThrows(ValidationException.class, () -> withTime(field, Duration.ofNanos(1_500_000))).getMessage()
      );
    }
    assertThrows(NullPointerException.class, () -> StormTrackingCache.builder().gracePeriod(null));
    assertThrows(NullPointerException.class, () -> StormTrackingCache.builder().graceInterval(null));
    assertThrows(NullPointerException.class, () -> StormTrackingCache.builder().inFlightTtl(null));
    assertThrows(NullPointerException.class, () -> StormTrackingCache.builder().sleep(null));

    // Whole seconds are held in seconds, up to Integer.MAX_VALUE of them; any other times in milliseconds, up to Integer.MAX_VALUE.
    Duration maxSeconds = Duration.ofSeconds(Integer.MAX_VALUE);
    StormTrackingCache longest = StormTrackingCache.builder().entryCapacity(1).gracePeriod(maxSeconds).graceInterval(maxSeconds).inFlightTtl(maxSeconds).build();
    assertEquals(maxSeconds, longest.gracePeriod());
    assertTrue(StormSettings.of(longest).seconds);
    Duration maxMillis = Duration.ofMillis(Integer.MAX_VALUE);
    StormTrackingCache fine = StormTrackingCache.builder().entryCapacity(1).gracePeriod(maxMillis).graceInterval(Duration.ofMillis(1500)).inFlightTtl(Duration.ofMillis(1500)).build();
    assertEquals(maxMillis, fine.gracePeriod());
    assertFalse(StormSettings.of(fine).seconds);
    assertEquals(Integer.MAX_VALUE, StormSettings.of(fine).gracePeriod);
    String range = "gracePeriod, graceInterval, and inFlightTtl must be whole seconds of at most 2147483647 seconds, or at most 2147483647 milliseconds";
    for (StormTrackingCache.Builder unrepresentable : Arrays.asList(
      StormTrackingCache.builder().entryCapacity(1).gracePeriod(maxSeconds.plusSeconds(1)).graceInterval(maxSeconds).inFlightTtl(maxSeconds),
      StormTrackingCache.builder().entryCapacity(1).gracePeriod(maxMillis.plusMillis(1)).graceInterval(Duration.ofMillis(1500)),
      StormTrackingCache.builder().entryCapacity(1).gracePeriod(Duration.ofSeconds(Long.MAX_VALUE)).graceInterval(maxSeconds).inFlightTtl(maxSeconds)
    )) {
      assertTrue(assertThrows(ValidationException.class, unrepresentable::build).getMessage().startsWith(range));
    }
    assertEquals(
      "`sleep` must be at most 2147483647 milliseconds",
      assertThrows(ValidationException.class, () -> withTime("sleep", maxMillis.plusMillis(1))).getMessage()
    );
    assertEquals(maxMillis, withTime("sleep", maxMillis).sleep());

    // The consistency rules compare the times, with StormTracker.dfy's message showing them as Durations.
    assertEquals(
      "For a StormCache : graceInterval must not exceed gracePeriod, yet configuration has graceInterval=PT10.001S and gracePeriod=PT10S. ",
      assertThrows(ValidationException.class, () -> withTime("graceInterval", Duration.ofMillis(10_001))).getMessage()
    );
    assertEquals(
      "For a StormCache : inFlightTTL must not exceed gracePeriod, yet configuration has inFlightTTL=PT11S and gracePeriod=PT10S. ",
      assertThrows(ValidationException.class, () -> withTime("inFlightTtl", Duration.ofSeconds(11))).getMessage()
    );
    assertEquals(
      "For a StormCache : ",
      assertThrows(ValidationException.class, () -> StormTrackingCache.builder().entryCapacity(1).graceInterval(Duration.ofSeconds(2)).inFlightTtl(Duration.ofSeconds(1)).build()).getMessage()
    );
    withTime("graceInterval", Duration.ofSeconds(10));
  }

  // Default settings with one time replaced; graceInterval and inFlightTtl follow a shorter grace period.
  private static StormTrackingCache withTime(String field, Duration time) {
    StormTrackingCache.Builder builder = StormTrackingCache.builder().entryCapacity(1);
    switch (field) {
      case "gracePeriod":
        return builder.gracePeriod(time).graceInterval(time).inFlightTtl(time).build();
      case "graceInterval":
        return builder.graceInterval(time).build();
      case "inFlightTtl":
        return builder.inFlightTtl(time).build();
      default:
        return builder.sleep(time).build();
    }
  }

  @Test
  void cacheKey() {
    byte[] bytes = { 0x00, (byte) 0xab, 0x0f, (byte) 0xff };
    CacheKey key = CacheKey.of(bytes);
    bytes[0] = 1;
    assertTrue(Arrays.equals(new byte[] { 0x00, (byte) 0xab, 0x0f, (byte) 0xff }, key.identifier()));
    key.identifier()[1] = 0;
    assertEquals("00ab0fff", key.toString());
    assertEquals(CacheKey.of(new byte[] { 0x00, (byte) 0xab, 0x0f, (byte) 0xff }), key);
    assertEquals(CacheKey.of(new byte[] { 0x00, (byte) 0xab, 0x0f, (byte) 0xff }).hashCode(), key.hashCode());
    assertNotEquals(CacheKey.of(new byte[] { 0x00, (byte) 0xab, 0x0f }), key);
    assertNotEquals(key, "00ab0fff");
    assertEquals("", CacheKey.of(new byte[0]).toString());
    assertThrows(NullPointerException.class, () -> CacheKey.of(null));
  }

  @Test
  void cacheEntry() {
    Instant created = Instant.ofEpochSecond(100);
    Instant expires = Instant.ofEpochSecond(200);
    CacheEntry branch = CacheEntry.builder().branchKeyMaterials(branchKey("a")).creationTime(created).expiryTime(expires).build();
    assertTrue(branch.branchKeyMaterials().isPresent());
    assertFalse(branch.beaconKeyMaterials().isPresent());
    assertEquals(created, branch.creationTime());
    assertEquals(expires, branch.expiryTime());
    assertEquals("CacheEntry[branch key, created 1970-01-01T00:01:40Z, expires 1970-01-01T00:03:20Z]", branch.toString());
    CacheEntry beacon = CacheEntry.builder().beaconKeyMaterials(beaconKey()).creationTime(created).expiryTime(expires).build();
    assertTrue(beacon.beaconKeyMaterials().isPresent());
    assertFalse(beacon.branchKeyMaterials().isPresent());
    assertTrue(beacon.toString().startsWith("CacheEntry[beacon key"));
    assertEquals(CacheEntry.builder().branchKeyMaterials(branchKey("a")).creationTime(created).expiryTime(expires).build(), branch);
    assertEquals(CacheEntry.builder().branchKeyMaterials(branchKey("a")).creationTime(created).expiryTime(expires).build().hashCode(), branch.hashCode());
    assertNotEquals(CacheEntry.builder().branchKeyMaterials(branchKey("b")).creationTime(created).expiryTime(expires).build(), branch);
    assertNotEquals(CacheEntry.builder().branchKeyMaterials(branchKey("a")).creationTime(expires).expiryTime(expires).build(), branch);
    assertNotEquals(CacheEntry.builder().branchKeyMaterials(branchKey("a")).creationTime(created).expiryTime(created).build(), branch);
    assertNotEquals(beacon, branch);
    BeaconKeyMaterials otherBeacon = KeyMaterialsAccess.beaconKey("other", EncryptionContext.empty(), null, Collections.emptyMap());
    assertNotEquals(CacheEntry.builder().beaconKeyMaterials(otherBeacon).creationTime(created).expiryTime(expires).build(), beacon);
    assertNotEquals(branch, "entry");
    assertThrows(ValidationException.class, () -> CacheEntry.builder().creationTime(created).expiryTime(expires).build());
    assertThrows(
      ValidationException.class,
      () -> CacheEntry.builder().branchKeyMaterials(branchKey("a")).beaconKeyMaterials(beaconKey()).creationTime(created).expiryTime(expires).build()
    );
    assertThrows(ValidationException.class, () -> CacheEntry.builder().branchKeyMaterials(branchKey("a")).expiryTime(expires).build());
    assertThrows(ValidationException.class, () -> CacheEntry.builder().branchKeyMaterials(branchKey("a")).creationTime(created).build());
    assertEquals(branch, branch.toBuilder().build());
    assertEquals(Instant.ofEpochSecond(300), branch.toBuilder().expiryTime(Instant.ofEpochSecond(300)).build().expiryTime());
  }

  @Test
  void builtInCachesStoreBranchAndBeaconKeys() {
    Instant now = Instant.now();
    for (CryptographicMaterialsCache cache : Arrays.asList(
      DefaultCache.builder().entryCapacity(5).build(),
      SingleThreadedCache.builder().entryCapacity(5).build(),
      MultiThreadedCache.builder().entryCapacity(5).entryPruningTailSize(2).build(),
      StormTrackingCache.builder().entryCapacity(5).build()
    )) {
      CacheEntry branch = CacheEntry.builder().branchKeyMaterials(branchKey("a")).creationTime(now).expiryTime(now.plusSeconds(1000)).build();
      CacheEntry beacon = CacheEntry.builder().beaconKeyMaterials(beaconKey()).creationTime(now).expiryTime(now.plusSeconds(1000)).build();
      put(cache, key("a"), branch);
      put(cache, key("b"), beacon);
      assertSame(branch, get(cache, key("a")).get());
      assertSame(beacon, get(cache, key("b")).get());
      cache.deleteCacheEntry(DeleteCacheEntryRequest.builder().key(key("a")).build());
      assertFalse(get(cache, key("a")).isPresent(), cache.toString());
      cache.deleteCacheEntry(DeleteCacheEntryRequest.builder().key(key("a")).build());
      // Expired: before this second.
      put(cache, key("c"), CacheEntry.builder().branchKeyMaterials(branchKey("c")).creationTime(now).expiryTime(now.minusSeconds(2)).build());
      assertFalse(get(cache, key("c")).isPresent(), cache.toString());
      assertThrows(NullPointerException.class, () -> cache.getCacheEntry(null));
      assertThrows(NullPointerException.class, () -> cache.putCacheEntry(null));
      assertThrows(NullPointerException.class, () -> cache.deleteCacheEntry(null));
    }
    assertThrows(ValidationException.class, () -> GetCacheEntryRequest.builder().key(null).build());
    assertThrows(ValidationException.class, () -> PutCacheEntryRequest.builder().key(null).entry(CacheEntry.builder().branchKeyMaterials(branchKey("a")).creationTime(now).expiryTime(now).build()).build());
    assertThrows(ValidationException.class, () -> PutCacheEntryRequest.builder().key(key("a")).entry(null).build());
    assertThrows(ValidationException.class, () -> DeleteCacheEntryRequest.builder().key(null).build());
    CryptographicMaterialsCache none = NoCache.create();
    put(none, key("a"), CacheEntry.builder().branchKeyMaterials(branchKey("a")).creationTime(now).expiryTime(now.plusSeconds(1000)).build());
    assertFalse(get(none, key("a")).isPresent());
  }

  // Expiry has whole-second resolution: an entry is returned until the end of its expiry second.
  @Test
  void expiryCountsWholeSeconds() {
    long[] wall = { 10_999 };
    CacheClock clock = new CacheClock() {
      @Override
      public long wallMillis() {
        return wall[0];
      }

      @Override
      public long monotonicMillis() {
        return wall[0];
      }
    };
    BuiltInCache cache = new BuiltInCache(Caches.singleThreaded(5, 1, clock));
    put(cache, key("a"), CacheEntry.builder().branchKeyMaterials(branchKey("a")).creationTime(Instant.EPOCH).expiryTime(Instant.ofEpochMilli(10_001)).build());
    assertTrue(get(cache, key("a")).isPresent());
    wall[0] = 11_000;
    assertFalse(get(cache, key("a")).isPresent());
  }

  // Register R13: a storm-tracking wait that outlives inFlightTtl is a retryable ThrottlingException.
  @Test
  void stormTrackingWaitTimeoutIsThrottling() {
    long[] now = { 10_000 };
    CacheClock clock = new CacheClock() {
      @Override
      public long wallMillis() {
        return now[0];
      }

      @Override
      public long monotonicMillis() {
        // Each read moves time on by 1 ms, so a waiting caller runs out of time.
        return now[0]++;
      }
    };
    StormTrackingCache settings = StormTrackingCache
      .builder()
      .entryCapacity(5)
      .gracePeriod(Duration.ofMillis(1000))
      .graceInterval(Duration.ofMillis(1))
      .inFlightTtl(Duration.ofMillis(5))
      .fanOut(1)
      .sleep(Duration.ofMillis(1))
      .build();
    BuiltInCache cache = new BuiltInCache(Caches.stormTracking(StormSettings.of(settings), clock));
    assertFalse(get(cache, key("a")).isPresent());
    ThrottlingException thrown = assertThrows(ThrottlingException.class, () -> get(cache, key("b")));
    assertEquals("Storm cache inFlightTTL exceeded.", thrown.getMessage());
    assertTrue(thrown.isRetryable());
  }

  private static Optional<CacheEntry> get(CryptographicMaterialsCache cache, CacheKey key) {
    return cache.getCacheEntry(GetCacheEntryRequest.builder().key(key).build()).entry();
  }

  private static void put(CryptographicMaterialsCache cache, CacheKey key, CacheEntry entry) {
    cache.putCacheEntry(PutCacheEntryRequest.builder().key(key).entry(entry).build());
  }

  private static CacheKey key(String id) {
    return CacheKey.of(id.getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }

  private static BranchKeyMaterials branchKey(String id) {
    return KeyMaterialsAccess.branchKey(id, "version", EncryptionContext.of("k", "v"), SecretBytes.copyOf(new byte[32]));
  }

  private static BeaconKeyMaterials beaconKey() {
    return KeyMaterialsAccess.beaconKey("beacon", EncryptionContext.empty(), SecretBytes.copyOf(new byte[32]), Collections.emptyMap());
  }
}
