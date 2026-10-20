// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.cache;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.mpl.EncryptionContext;
import software.amazon.cryptography.mpl.SecretBytes;
import software.amazon.cryptography.mpl.exceptions.ThrottlingException;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.KeyMaterialsAccess;
import software.amazon.cryptography.mpl.internal.cache.BuiltInCache;
import software.amazon.cryptography.mpl.internal.cache.CacheClock;
import software.amazon.cryptography.mpl.internal.cache.CacheSpec;
import software.amazon.cryptography.mpl.internal.cache.Caches;
import software.amazon.cryptography.mpl.keystore.BeaconKeyMaterials;
import software.amazon.cryptography.mpl.keystore.BranchKeyMaterials;

// The public cache API: CacheType factories, storm-tracking settings, keys, entries, and the built-in caches.
class CacheApiTest {

  @Test
  void cacheTypeKinds() {
    assertEquals(CacheType.Kind.DEFAULT, CacheType.defaultCache(1).kind());
    assertEquals(CacheType.Kind.NO_CACHE, CacheType.noCache().kind());
    assertEquals(CacheType.Kind.SINGLE_THREADED, CacheType.singleThreaded(1).kind());
    assertEquals(CacheType.Kind.SINGLE_THREADED, CacheType.singleThreaded(1, 2).kind());
    assertEquals(CacheType.Kind.MULTI_THREADED, CacheType.multiThreaded(1).kind());
    assertEquals(CacheType.Kind.MULTI_THREADED, CacheType.multiThreaded(1, 2).kind());
    assertEquals(CacheType.Kind.STORM_TRACKING, CacheType.stormTracking(StormTrackingCache.builder().entryCapacity(1).build()).kind());
    CryptographicMaterialsCache shared = CryptographicMaterialsCache.create(CacheType.noCache());
    assertEquals(CacheType.Kind.SHARED, CacheType.shared(shared).kind());
    assertSame(shared, CacheSpec.of(CacheType.shared(shared)).shared);
  }

  @Test
  void cacheTypeSpecs() {
    CacheSpec single = CacheSpec.of(CacheType.singleThreaded(7));
    assertEquals(7, single.entryCapacity);
    assertEquals(1, single.entryPruningTailSize);
    CacheSpec multi = CacheSpec.of(CacheType.multiThreaded(8, 3));
    assertEquals(8, multi.entryCapacity);
    assertEquals(3, multi.entryPruningTailSize);
    assertEquals(3, CacheSpec.of(CacheType.singleThreaded(8, 3)).entryPruningTailSize);
    assertEquals(1, CacheSpec.of(CacheType.multiThreaded(8)).entryPruningTailSize);
    // StormTracker.dfy DefaultStorm, in milliseconds.
    StormTrackingCache defaults = StormTrackingCache
      .builder()
      .entryCapacity(9)
      .entryPruningTailSize(1)
      .gracePeriod(10_000)
      .graceInterval(1000)
      .fanOut(20)
      .inFlightTtl(10_000)
      .sleepMilli(20)
      .timeUnits(TimeUnits.MILLISECONDS)
      .build();
    assertEquals(defaults, CacheSpec.of(CacheType.defaultCache(9)).stormTracking);
    StormTrackingCache settings = StormTrackingCache.builder().entryCapacity(4).build();
    assertSame(settings, CacheSpec.of(CacheType.stormTracking(settings)).stormTracking);
    assertNull(CacheSpec.of(CacheType.noCache()).stormTracking);
  }

  @Test
  void cacheTypeValidation() {
    List<Supplier<CacheType>> invalidCapacity = Arrays.asList(
      () -> CacheType.defaultCache(0),
      () -> CacheType.defaultCache(-1),
      () -> CacheType.singleThreaded(0),
      () -> CacheType.singleThreaded(0, 1),
      () -> CacheType.multiThreaded(0),
      () -> CacheType.multiThreaded(Integer.MIN_VALUE, 1)
    );
    for (Supplier<CacheType> create : invalidCapacity) {
      assertEquals("`entryCapacity` must be greater than or equal to 1", assertThrows(ValidationException.class, create::get).getMessage());
    }
    for (Supplier<CacheType> create : Arrays.<Supplier<CacheType>>asList(() -> CacheType.singleThreaded(1, 0), () -> CacheType.multiThreaded(1, -1))) {
      assertEquals(
        "`entryPruningTailSize` must be greater than or equal to 1",
        assertThrows(ValidationException.class, create::get).getMessage()
      );
    }
    assertThrows(NullPointerException.class, () -> CacheType.stormTracking(null));
    assertThrows(NullPointerException.class, () -> CacheType.shared(null));
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
    assertEquals(StormTrackingCache.DEFAULT_SLEEP_MILLI, settings.sleepMilli());
    assertEquals(TimeUnits.SECONDS, settings.timeUnits());
    assertEquals(
      Arrays.asList(1, 10, 1, 20, 10, 20),
      Arrays.asList(
        StormTrackingCache.DEFAULT_ENTRY_PRUNING_TAIL_SIZE,
        StormTrackingCache.DEFAULT_GRACE_PERIOD,
        StormTrackingCache.DEFAULT_GRACE_INTERVAL,
        StormTrackingCache.DEFAULT_FAN_OUT,
        StormTrackingCache.DEFAULT_IN_FLIGHT_TTL,
        StormTrackingCache.DEFAULT_SLEEP_MILLI
      )
    );
  }

  @Test
  void stormTrackingSettersAndValueSemantics() {
    StormTrackingCache settings = StormTrackingCache
      .builder()
      .entryCapacity(2)
      .entryPruningTailSize(3)
      .gracePeriod(9)
      .graceInterval(4)
      .fanOut(6)
      .inFlightTtl(7)
      .sleepMilli(8)
      .timeUnits(TimeUnits.MILLISECONDS)
      .build();
    assertEquals(
      Arrays.<Object>asList(2, 3, 9, 4, 6, 7, 8, TimeUnits.MILLISECONDS),
      Arrays.<Object>asList(
        settings.entryCapacity(),
        settings.entryPruningTailSize(),
        settings.gracePeriod(),
        settings.graceInterval(),
        settings.fanOut(),
        settings.inFlightTtl(),
        settings.sleepMilli(),
        settings.timeUnits()
      )
    );
    assertEquals(
      "StormTrackingCache[entryCapacity=2, entryPruningTailSize=3, gracePeriod=9, graceInterval=4, fanOut=6, inFlightTtl=7, " +
      "sleepMilli=8, timeUnits=MILLISECONDS]",
      settings.toString()
    );
    StormTrackingCache same = StormTrackingCache
      .builder()
      .entryCapacity(2)
      .entryPruningTailSize(3)
      .gracePeriod(9)
      .graceInterval(4)
      .fanOut(6)
      .inFlightTtl(7)
      .sleepMilli(8)
      .timeUnits(TimeUnits.MILLISECONDS)
      .build();
    assertEquals(settings, same);
    assertEquals(settings.hashCode(), same.hashCode());
    assertNotEquals(settings, "settings");
    List<StormTrackingCache> different = Arrays.asList(
      StormTrackingCache.builder().entryCapacity(1).entryPruningTailSize(3).gracePeriod(9).graceInterval(4).fanOut(6).inFlightTtl(7).sleepMilli(8).timeUnits(TimeUnits.MILLISECONDS).build(),
      StormTrackingCache.builder().entryCapacity(2).entryPruningTailSize(1).gracePeriod(9).graceInterval(4).fanOut(6).inFlightTtl(7).sleepMilli(8).timeUnits(TimeUnits.MILLISECONDS).build(),
      StormTrackingCache.builder().entryCapacity(2).entryPruningTailSize(3).gracePeriod(8).graceInterval(4).fanOut(6).inFlightTtl(7).sleepMilli(8).timeUnits(TimeUnits.MILLISECONDS).build(),
      StormTrackingCache.builder().entryCapacity(2).entryPruningTailSize(3).gracePeriod(9).graceInterval(3).fanOut(6).inFlightTtl(7).sleepMilli(8).timeUnits(TimeUnits.MILLISECONDS).build(),
      StormTrackingCache.builder().entryCapacity(2).entryPruningTailSize(3).gracePeriod(9).graceInterval(4).fanOut(5).inFlightTtl(7).sleepMilli(8).timeUnits(TimeUnits.MILLISECONDS).build(),
      StormTrackingCache.builder().entryCapacity(2).entryPruningTailSize(3).gracePeriod(9).graceInterval(4).fanOut(6).inFlightTtl(6).sleepMilli(8).timeUnits(TimeUnits.MILLISECONDS).build(),
      StormTrackingCache.builder().entryCapacity(2).entryPruningTailSize(3).gracePeriod(9).graceInterval(4).fanOut(6).inFlightTtl(7).sleepMilli(9).timeUnits(TimeUnits.MILLISECONDS).build(),
      StormTrackingCache.builder().entryCapacity(2).entryPruningTailSize(3).gracePeriod(9).graceInterval(4).fanOut(6).inFlightTtl(7).sleepMilli(8).timeUnits(TimeUnits.SECONDS).build()
    );
    for (StormTrackingCache other : different) {
      assertNotEquals(settings, other);
    }
  }

  @Test
  void stormTrackingValidation() {
    assertEquals(
      "Missing value for required field `entryCapacity`",
      assertThrows(ValidationException.class, () -> StormTrackingCache.builder().build()).getMessage()
    );
    String[] fields = { "entryCapacity", "entryPruningTailSize", "gracePeriod", "graceInterval", "fanOut", "inFlightTTL", "sleepMilli" };
    for (String field : fields) {
      for (int value : new int[] { 0, -1 }) {
        StormTrackingCache.Builder builder = StormTrackingCache.builder().entryCapacity(1);
        switch (field) {
          case "entryCapacity":
            builder.entryCapacity(value);
            break;
          case "entryPruningTailSize":
            builder.entryPruningTailSize(value);
            break;
          case "gracePeriod":
            builder.gracePeriod(value);
            break;
          case "graceInterval":
            builder.graceInterval(value);
            break;
          case "fanOut":
            builder.fanOut(value);
            break;
          case "inFlightTTL":
            builder.inFlightTtl(value);
            break;
          default:
            builder.sleepMilli(value);
        }
        assertEquals("`" + field + "` must be greater than or equal to 1", assertThrows(ValidationException.class, builder::build).getMessage());
      }
    }
    assertThrows(NullPointerException.class, () -> StormTrackingCache.builder().timeUnits(null));
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
    StormTrackingCache.builder().entryCapacity(1).gracePeriod(5).graceInterval(5).inFlightTtl(5).build();
  }

  private static String inconsistent(int gracePeriod, int graceInterval, int inFlightTtl) {
    StormTrackingCache.Builder builder = StormTrackingCache
      .builder()
      .entryCapacity(1)
      .gracePeriod(gracePeriod)
      .graceInterval(graceInterval)
      .inFlightTtl(inFlightTtl);
    return assertThrows(ValidationException.class, builder::build).getMessage();
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
    CacheEntry branch = CacheEntry.of(branchKey("a"), created, expires);
    assertTrue(branch.branchKeyMaterials().isPresent());
    assertFalse(branch.beaconKeyMaterials().isPresent());
    assertEquals(created, branch.creationTime());
    assertEquals(expires, branch.expiryTime());
    assertEquals("CacheEntry[branch key, created 1970-01-01T00:01:40Z, expires 1970-01-01T00:03:20Z]", branch.toString());
    CacheEntry beacon = CacheEntry.of(beaconKey(), created, expires);
    assertTrue(beacon.beaconKeyMaterials().isPresent());
    assertFalse(beacon.branchKeyMaterials().isPresent());
    assertTrue(beacon.toString().startsWith("CacheEntry[beacon key"));
    assertEquals(CacheEntry.of(branchKey("a"), created, expires), branch);
    assertEquals(CacheEntry.of(branchKey("a"), created, expires).hashCode(), branch.hashCode());
    assertNotEquals(CacheEntry.of(branchKey("b"), created, expires), branch);
    assertNotEquals(CacheEntry.of(branchKey("a"), expires, expires), branch);
    assertNotEquals(CacheEntry.of(branchKey("a"), created, created), branch);
    assertNotEquals(beacon, branch);
    BeaconKeyMaterials otherBeacon = KeyMaterialsAccess.beaconKey("other", EncryptionContext.empty(), null, Collections.emptyMap());
    assertNotEquals(CacheEntry.of(otherBeacon, created, expires), beacon);
    assertNotEquals(branch, "entry");
    assertThrows(NullPointerException.class, () -> CacheEntry.of((BranchKeyMaterials) null, created, expires));
    assertThrows(NullPointerException.class, () -> CacheEntry.of((BeaconKeyMaterials) null, created, expires));
    assertThrows(NullPointerException.class, () -> CacheEntry.of(branchKey("a"), null, expires));
    assertThrows(NullPointerException.class, () -> CacheEntry.of(branchKey("a"), created, null));
  }

  // A consumer that takes a CacheType, such as a DB-ESDK beacon key source, gets the instance back from a shared one.
  @Test
  void aSharedTypeHoldsItsCache() {
    CryptographicMaterialsCache shared = CryptographicMaterialsCache.create(CacheType.noCache());
    assertSame(shared, CryptographicMaterialsCache.create(CacheType.shared(shared)));
    for (CacheType other : Arrays.asList(CacheType.defaultCache(1), CacheType.noCache(), CacheType.singleThreaded(1), CacheType.multiThreaded(1),
        CacheType.stormTracking(StormTrackingCache.builder().entryCapacity(1).build()))) {
      assertNotSame(shared, CryptographicMaterialsCache.create(other), other.kind().toString());
    }
    assertThrows(NullPointerException.class, () -> CryptographicMaterialsCache.create(null));
  }

  @Test
  void builtInCachesStoreBranchAndBeaconKeys() {
    Instant now = Instant.now();
    for (CacheType type : Arrays.asList(
      CacheType.defaultCache(5),
      CacheType.singleThreaded(5),
      CacheType.multiThreaded(5, 2),
      CacheType.stormTracking(StormTrackingCache.builder().entryCapacity(5).build())
    )) {
      CryptographicMaterialsCache cache = CryptographicMaterialsCache.create(type);
      CacheEntry branch = CacheEntry.of(branchKey("a"), now, now.plusSeconds(1000));
      CacheEntry beacon = CacheEntry.of(beaconKey(), now, now.plusSeconds(1000));
      put(cache, key("a"), branch);
      put(cache, key("b"), beacon);
      assertSame(branch, get(cache, key("a")).get());
      assertSame(beacon, get(cache, key("b")).get());
      cache.deleteCacheEntry(DeleteCacheEntryRequest.of(key("a")));
      assertFalse(get(cache, key("a")).isPresent(), type.kind().toString());
      cache.deleteCacheEntry(DeleteCacheEntryRequest.of(key("a")));
      // Expired: before this second.
      put(cache, key("c"), CacheEntry.of(branchKey("c"), now, now.minusSeconds(2)));
      assertFalse(get(cache, key("c")).isPresent(), type.kind().toString());
      assertThrows(NullPointerException.class, () -> cache.getCacheEntry(null));
      assertThrows(NullPointerException.class, () -> cache.putCacheEntry(null));
      assertThrows(NullPointerException.class, () -> cache.deleteCacheEntry(null));
    }
    assertThrows(ValidationException.class, () -> GetCacheEntryRequest.of(null));
    assertThrows(ValidationException.class, () -> PutCacheEntryRequest.of(null, CacheEntry.of(branchKey("a"), now, now)));
    assertThrows(ValidationException.class, () -> PutCacheEntryRequest.of(key("a"), null));
    assertThrows(ValidationException.class, () -> DeleteCacheEntryRequest.of(null));
    CryptographicMaterialsCache none = CryptographicMaterialsCache.create(CacheType.noCache());
    put(none, key("a"), CacheEntry.of(branchKey("a"), now, now.plusSeconds(1000)));
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
    BuiltInCache cache = new BuiltInCache(Caches.engine(CacheType.singleThreaded(5), clock));
    put(cache, key("a"), CacheEntry.of(branchKey("a"), Instant.EPOCH, Instant.ofEpochMilli(10_001)));
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
      .gracePeriod(1000)
      .graceInterval(1)
      .inFlightTtl(5)
      .fanOut(1)
      .sleepMilli(1)
      .timeUnits(TimeUnits.MILLISECONDS)
      .build();
    BuiltInCache cache = new BuiltInCache(Caches.engine(CacheType.stormTracking(settings), clock));
    assertFalse(get(cache, key("a")).isPresent());
    ThrottlingException thrown = assertThrows(ThrottlingException.class, () -> get(cache, key("b")));
    assertEquals("Storm cache inFlightTTL exceeded.", thrown.getMessage());
    assertTrue(thrown.isRetryable());
  }

  private static Optional<CacheEntry> get(CryptographicMaterialsCache cache, CacheKey key) {
    return cache.getCacheEntry(GetCacheEntryRequest.of(key)).entry();
  }

  private static void put(CryptographicMaterialsCache cache, CacheKey key, CacheEntry entry) {
    cache.putCacheEntry(PutCacheEntryRequest.of(key, entry));
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
