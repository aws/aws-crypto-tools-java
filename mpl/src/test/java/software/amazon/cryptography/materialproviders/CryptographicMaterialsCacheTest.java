// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import software.amazon.cryptography.keystore.model.BeaconKeyMaterials;
import software.amazon.cryptography.keystore.model.BranchKeyMaterials;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteInfo;
import software.amazon.cryptography.materialproviders.model.CacheType;
import software.amazon.cryptography.materialproviders.model.CreateCryptographicMaterialsCacheInput;
import software.amazon.cryptography.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.model.DefaultCache;
import software.amazon.cryptography.materialproviders.model.DeleteCacheEntryInput;
import software.amazon.cryptography.materialproviders.model.ESDKAlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.model.GetCacheEntryInput;
import software.amazon.cryptography.materialproviders.model.InitializeDecryptionMaterialsInput;
import software.amazon.cryptography.materialproviders.model.InitializeEncryptionMaterialsInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;
import software.amazon.cryptography.materialproviders.model.Materials;
import software.amazon.cryptography.materialproviders.model.MultiThreadedCache;
import software.amazon.cryptography.materialproviders.model.NoCache;
import software.amazon.cryptography.materialproviders.model.PutCacheEntryInput;
import software.amazon.cryptography.materialproviders.model.SingleThreadedCache;
import software.amazon.cryptography.materialproviders.model.StormTrackingCache;
import software.amazon.cryptography.materialproviders.model.TimeUnits;
import software.amazon.cryptography.materialproviders.model.UpdateUsageMetadataInput;

// Differential tests of CreateCryptographicMaterialsCache and the caches it returns, against the published Dafny-based MPL.
// Each cache operation runs on a native and a reference cache in lock step and must give the same result or exception.
// Real clocks drive both, so the scripts use expiry times far from now; time-dependent storm tracking runs natively
// with an injected clock (StormTrackerTest).
@Timeout(120)
class CryptographicMaterialsCacheTest {

  private static final String MISSING = "throws software.amazon.cryptography.materialproviders.model.EntryDoesNotExist: Entry does not exist";
  private static final String EXPIRED = "throws software.amazon.cryptography.materialproviders.model.EntryDoesNotExist: Entry past TTL";
  private static final String WAIT_EXCEEDED =
    "throws software.amazon.cryptography.materialproviders.model.InFlightTTLExceeded: Storm cache inFlightTTL exceeded.";

  private final MaterialProviders mpl = MaterialProviders
    .builder()
    .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
    .build();
  private final Object reference = ReferenceMpl.materialProviders();
  private final long now = System.currentTimeMillis() / 1000;
  private final long live = now + 100_000;
  private final long expired = now - 100;

  @Test
  void createValidatesStormTrackingSettings() {
    Map<String, Integer> outcomes = new TreeMap<>();
    int[] values = { 1, 2, 3 };
    for (int gracePeriod : values) {
      for (int graceInterval : values) {
        for (int inFlightTTL : values) {
          for (TimeUnits units : Arrays.asList(null, TimeUnits.Seconds, TimeUnits.Milliseconds)) {
            for (int tail : new int[] { 1, 2 }) {
              StormTrackingCache.Builder storm = StormTrackingCache
                .builder()
                .entryCapacity(5)
                .gracePeriod(gracePeriod)
                .graceInterval(graceInterval)
                .fanOut(3)
                .inFlightTTL(inFlightTTL)
                .sleepMilli(7)
                .timeUnits(units)
                .entryPruningTailSize(tail);
              String outcome = assertCreateSame(CacheType.builder().StormTracking(storm.build()).build());
              outcomes.merge(outcome, 1, Integer::sum);
            }
          }
        }
      }
    }
    // Each rule fails alone and in combination, including the one BadCacheMsg does not describe.
    String prefix = "throws software.amazon.cryptography.materialproviders.model.AwsCryptographicMaterialProvidersException: For a StormCache : ";
    String interval = "graceInterval must not exceed gracePeriod";
    String ttl = "inFlightTTL must not exceed gracePeriod";
    Map<String, Integer> kinds = new TreeMap<>();
    for (Map.Entry<String, Integer> outcome : outcomes.entrySet()) {
      String o = outcome.getKey();
      String kind = o.equals("\"created\"") ? "created" : o.equals(prefix) ? "prefix only" : !o.startsWith(prefix)
        ? o
        : (o.contains(interval) ? "interval " : "") + (o.contains(ttl) ? "ttl" : "");
      kinds.merge(kind, outcome.getValue(), Integer::sum);
    }
    // 3 x 3 x 3 settings, 3 time units, 2 tail sizes.
    assertEquals("{created=60, interval =24, interval ttl=30, prefix only=24, ttl=24}", kinds.toString());
  }

  @Test
  void createOtherKinds() {
    for (CacheType type : allKinds(3)) {
      assertEquals("\"created\"", assertCreateSame(type));
    }
    assertCreateSame(CacheType.builder().Default(DefaultCache.builder().entryCapacity(Integer.MAX_VALUE).build()).build());
  }

  @Test
  void createRejectsSharedCache() {
    ICryptographicMaterialsCache nativeShared = mpl.CreateCryptographicMaterialsCache(input(noCache()));
    Object referenceShared = ReferenceMpl.call(reference, "CreateCryptographicMaterialsCache", input(noCache()));
    CreateCryptographicMaterialsCacheInput nativeInput = input(CacheType.builder().Shared(nativeShared).build());
    Object referenceInput = ReferenceMpl.build(
      "materialproviders.model.CreateCryptographicMaterialsCacheInput",
      "cache",
      ReferenceMpl.build("materialproviders.model.CacheType", "Shared", referenceShared)
    );
    String expected = ReferenceMpl.outcome(() -> ReferenceMpl.call(reference, "CreateCryptographicMaterialsCache", referenceInput));
    assertEquals(
      "throws software.amazon.cryptography.materialproviders.model.AwsCryptographicMaterialProvidersException: " +
      "CreateCryptographicMaterialsCache should never be called with Shared CacheType.",
      expected
    );
    assertEquals(expected, ReferenceMpl.outcome(() -> mpl.CreateCryptographicMaterialsCache(nativeInput)));
  }

  @Test
  void putGetDelete() {
    for (CacheType type : allKinds(5)) {
      int expectedHits = type.No() != null ? 0 : 4;
      assertSame(type, c -> {
        c.getAndClear("a");
        c.step("PutCacheEntry", put("a", live));
        c.step("PutCacheEntry", put("b", live));
        c.getAndClear("a");
        c.getAndClear("b");
        c.step("DeleteCacheEntry", delete("a"));
        c.getAndClear("a");
        c.getAndClear("b");
        c.step("DeleteCacheEntry", delete("a"));
        // An identifier is its bytes [0, limit), whatever the buffer's position.
        ByteBuffer shifted = ByteBuffer.wrap("bxyz".getBytes(StandardCharsets.UTF_8), 0, 1);
        shifted.position(1);
        c.step("GetCacheEntry", GetCacheEntryInput.builder().identifier(shifted).build());
        c.step("DeleteCacheEntry", delete("b"));
        c.getAndClear("b");
        assertEquals(expectedHits, c.hits);
      });
    }
  }

  @Test
  void capacityEvictsLeastRecentlyUsed() {
    for (CacheType type : capacityKinds(3)) {
      assertSame(type, c -> {
        c.step("PutCacheEntry", put("a", live));
        c.step("PutCacheEntry", put("b", live));
        c.step("PutCacheEntry", put("c", live));
        c.getAndClear("a");
        c.step("PutCacheEntry", put("d", live)); // evicts b
        c.getAndClear("b");
        c.step("PutCacheEntry", put("c", live, "c2")); // replaces c and makes it the most recent
        c.step("PutCacheEntry", put("e", live)); // evicts a
        for (String id : new String[] { "a", "b", "c", "d", "e" }) {
          c.getAndClear(id);
        }
        c.step("PutCacheEntry", put("f", live)); // evicts c, the least recently read
        for (String id : new String[] { "c", "d", "e", "f" }) {
          c.getAndClear(id);
        }
        assertEquals(7, c.hits);
      });
    }
  }

  @Test
  void replacingAnEntryMakesItTheMostRecent() {
    for (CacheType type : capacityKinds(3)) {
      assertSame(type, c -> {
        c.step("PutCacheEntry", put("a", live));
        c.step("PutCacheEntry", put("b", live));
        c.step("PutCacheEntry", put("a", live, "a2"));
        c.step("PutCacheEntry", put("c", live));
        c.step("PutCacheEntry", put("d", live)); // evicts b
        for (String id : new String[] { "a", "b", "c", "d" }) {
          c.getAndClear(id);
        }
        assertEquals(3, c.hits);
      });
    }
  }

  @Test
  void capacityOneKeepsTheLastEntry() {
    for (CacheType type : capacityKinds(1)) {
      assertSame(type, c -> {
        c.step("PutCacheEntry", put("a", live));
        c.step("PutCacheEntry", put("b", live));
        c.getAndClear("a");
        c.getAndClear("b");
        assertEquals(1, c.hits);
      });
    }
  }

  @Test
  void expiredEntriesAreNotReturnedAndArePruned() {
    for (CacheType type : capacityKinds(10)) {
      assertSame(type, c -> {
        c.step("PutCacheEntry", put("x", expired));
        c.getAndClear("x");
        c.step("PutCacheEntry", put("y", now + 100));
        c.getAndClear("y");
        c.step("DeleteCacheEntry", delete("y"));
        // Four expired entries at the least recently used end; a hit prunes up to entryPruningTailSize of them.
        // A pruned entry reads as "does not exist", one still stored as "past TTL".
        for (String id : new String[] { "e1", "e2", "e3", "e4" }) {
          c.step("PutCacheEntry", put(id, expired));
        }
        c.step("PutCacheEntry", put("live", live));
        c.getAndClear("live");
        for (String id : new String[] { "e1", "e2", "e3", "e4" }) {
          c.getAndClear(id);
        }
        c.getAndClear("live");
        assertEquals(3, c.hits);
      });
    }
  }

  @Test
  void pruningStopsAtTheFirstLiveEntry() {
    for (CacheType type : capacityKinds(10)) {
      assertSame(type, c -> {
        c.step("PutCacheEntry", put("old", expired));
        c.step("PutCacheEntry", put("middle", live));
        c.step("PutCacheEntry", put("young", expired));
        c.step("PutCacheEntry", put("hot", live));
        c.getAndClear("hot");
        c.getAndClear("young");
        c.getAndClear("old");
        assertEquals(1, c.hits);
      });
    }
  }

  @Test
  void usageMetadata() {
    for (CacheType type : allKinds(5)) {
      assertSame(type, c -> {
        c.step("PutCacheEntry", put("a", live).toBuilder().messagesUsed(5).bytesUsed(7).build());
        c.step("UpdateUsageMetadata", usage("a", 3));
        c.step("UpdateUsageMetadata", usage("a", 0));
        c.step("UpdateUsageMetadata", usage("missing", 3));
        c.getAndClear("a");
        // Counters at the int limits: the update removes the entry.
        c.step("PutCacheEntry", put("m", live).toBuilder().messagesUsed(Integer.MAX_VALUE).build());
        c.step("UpdateUsageMetadata", usage("m", 0));
        c.getAndClear("m");
        c.step("PutCacheEntry", put("b", live).toBuilder().bytesUsed(Integer.MAX_VALUE).build());
        c.step("UpdateUsageMetadata", usage("b", 1));
        c.getAndClear("b");
        // Up to the Dafny constant 0x7999_9999 both keep counting.
        c.step("PutCacheEntry", put("n", live).toBuilder().messagesUsed(0x7999_9997).bytesUsed(0x7999_9990).build());
        c.step("UpdateUsageMetadata", usage("n", 9));
        c.getAndClear("n");
        // Reading does not count as a use.
        c.getAndClear("n");
      });
    }
  }

  // B6: LocalCMC.dfy compares the counters with 0x7999_9999 instead of the int maximum, and removes the entry here.
  // The native core has no counters (R4); the adapter keeps the Dafny limit.
  @Test
  void usageCountersStopAtTheDafnyLimit() {
    for (CacheType type : capacityKinds(5)) {
      Script script = c -> {
        c.step("PutCacheEntry", put("m", live).toBuilder().messagesUsed(0x7999_9999).bytesUsed(0x7999_9999).build());
        c.step("UpdateUsageMetadata", usage("m", 1));
        c.step("GetCacheEntry", get("m"));
      };
      Steps referenceSteps = new Steps(ReferenceMpl.call(reference, "CreateCryptographicMaterialsCache", input(type)), null);
      script.run(referenceSteps);
      Steps nativeSteps = new Steps(null, mpl.CreateCryptographicMaterialsCache(input(type)));
      script.run(nativeSteps);
      assertTrue(referenceSteps.outcomes.get(2).endsWith(MISSING), referenceSteps.outcomes.get(2));
      assertEquals(referenceSteps.outcomes, nativeSteps.outcomes);
    }
  }

  @Test
  void materialsRoundTrip() {
    List<Materials> materials = new ArrayList<>();
    materials.add(Materials.builder().BranchKey(branchKey("k")).build());
    materials.add(
      Materials.builder().BranchKey(branchKey("k").toBuilder().encryptionContext(Collections.emptyMap()).build()).build()
    );
    BeaconKeyMaterials beacon = BeaconKeyMaterials
      .builder()
      .beaconKeyIdentifier("beacon")
      .encryptionContext(map("e", "f"))
      .beaconKey(bytes("beacon key"))
      .hmacKeys(Collections.singletonMap("name", bytes("hmac")))
      .build();
    materials.add(Materials.builder().BeaconKey(beacon).build());
    materials.add(Materials.builder().BeaconKey(beacon.toBuilder().beaconKey(null).hmacKeys(null).build()).build());
    materials.add(Materials.builder().BeaconKey(beacon.toBuilder().hmacKeys(Collections.emptyMap()).build()).build());
    EncryptionMaterials encryption = encryptionMaterials();
    materials.add(Materials.builder().Encryption(encryption).build());
    materials.add(
      Materials
        .builder()
        .Encryption(encryption.toBuilder().symmetricSigningKeys(Collections.emptyList()).signingKey(bytes("sk")).build())
        .build()
    );
    materials.add(
      Materials
        .builder()
        .Encryption(encryption.toBuilder().symmetricSigningKeys(Collections.singletonList(bytes("sym"))).build())
        .build()
    );
    // The cache does not check materials: an inconsistent suite description comes back as stored.
    AlgorithmSuiteInfo wrongSuite = encryption.algorithmSuite().toBuilder().messageVersion(7).binaryId(bytes("zz")).build();
    materials.add(Materials.builder().Encryption(encryption.toBuilder().algorithmSuite(wrongSuite).build()).build());
    DecryptionMaterials decryption = decryptionMaterials();
    materials.add(Materials.builder().Decryption(decryption).build());
    materials.add(
      Materials
        .builder()
        .Decryption(
          decryption
            .toBuilder()
            .plaintextDataKey(bytes("0123456789abcdef"))
            .verificationKey(bytes("vk"))
            .symmetricSigningKey(bytes("ssk"))
            .build()
        )
        .build()
    );
    for (CacheType type : capacityKinds(20)) {
      assertSame(type, c -> {
        for (int i = 0; i < materials.size(); i++) {
          c.step("PutCacheEntry", put("m" + i, live).toBuilder().materials(materials.get(i)).build());
          c.getAndClear("m" + i);
        }
        assertEquals(materials.size(), c.hits);
      });
    }
  }

  @Test
  void cachedMaterialsAreCopies() {
    for (CacheType type : capacityKinds(5)) {
      assertSame(type, c -> {
        // Bytes [0, limit) of each buffer; later changes to the caller's buffer and map do not reach the cache.
        ByteBuffer key = ByteBuffer.wrap("0123456789abcdefXYZ".getBytes(StandardCharsets.UTF_8), 0, 16);
        key.position(3);
        Map<String, String> context = new HashMap<>(map("a", "b"));
        BranchKeyMaterials materials = branchKey("k").toBuilder().branchKey(key).encryptionContext(context).build();
        c.step("PutCacheEntry", put("k", live).toBuilder().materials(Materials.builder().BranchKey(materials).build()).build());
        key.put(0, (byte) 'Q');
        context.put("x", "y");
        c.getAndClear("k");
        assertEquals(1, c.hits);
      });
    }
  }

  @Test
  void stringsMustEncodeAsUtf8() {
    String lone = "\uD800";
    List<Materials> invalid = Arrays.asList(
      Materials.builder().BranchKey(branchKey("k").toBuilder().branchKeyVersion(lone).build()).build(),
      Materials.builder().BranchKey(branchKey("k").toBuilder().encryptionContext(map(lone, "v")).build()).build(),
      Materials.builder().BranchKey(branchKey("k").toBuilder().encryptionContext(map("k", lone)).build()).build(),
      Materials
        .builder()
        .BeaconKey(BeaconKeyMaterials.builder().beaconKeyIdentifier("b").encryptionContext(map(lone, "v")).build())
        .build(),
      Materials.builder().Encryption(encryptionMaterials().toBuilder().encryptionContext(map("k", lone)).build()).build(),
      Materials
        .builder()
        .Encryption(encryptionMaterials().toBuilder().requiredEncryptionContextKeys(Collections.singletonList(lone)).build())
        .build(),
      Materials
        .builder()
        .Encryption(
          encryptionMaterials()
            .toBuilder()
            .encryptedDataKeys(
              Collections.singletonList(
                EncryptedDataKey.builder().keyProviderId(lone).keyProviderInfo(bytes("i")).ciphertext(bytes("c")).build()
              )
            )
            .build()
        )
        .build(),
      Materials.builder().Decryption(decryptionMaterials().toBuilder().encryptionContext(map(lone, "v")).build()).build(),
      Materials
        .builder()
        .Decryption(decryptionMaterials().toBuilder().requiredEncryptionContextKeys(Collections.singletonList(lone)).build())
        .build()
    );
    // Strings Dafny keeps as UTF-16 accept lone surrogates.
    List<Materials> valid = Arrays.asList(
      Materials.builder().BranchKey(branchKey("k").toBuilder().branchKeyIdentifier(lone).build()).build(),
      Materials.builder().BeaconKey(BeaconKeyMaterials.builder().beaconKeyIdentifier(lone).encryptionContext(map()).build()).build(),
      Materials
        .builder()
        .BeaconKey(
          BeaconKeyMaterials
            .builder()
            .beaconKeyIdentifier("b")
            .encryptionContext(map())
            .hmacKeys(Collections.singletonMap(lone, bytes("h")))
            .build()
        )
        .build()
    );
    for (CacheType type : capacityKinds(5)) {
      assertSame(type, c -> {
        for (Materials m : invalid) {
          String outcome = c.step("PutCacheEntry", put("s", live).toBuilder().materials(m).build());
          assertEquals("throws java.lang.RuntimeException: Could not encode input to Dafny Bytes.", outcome);
          c.getAndClear("s");
        }
        for (Materials m : valid) {
          c.step("PutCacheEntry", put("s", live).toBuilder().materials(m).build());
          c.getAndClear("s");
        }
        assertEquals(valid.size(), c.hits);
      });
    }
  }

  // Inside the grace period a storm-tracking cache returns a miss to one caller, which refreshes the entry,
  // and the entry to the others.
  @Test
  void stormTrackingRefreshesInsideTheGracePeriod() {
    StormTrackingCache.Builder seconds = storm(10).entryPruningTailSize(1).gracePeriod(200_000).graceInterval(100_000).inFlightTTL(100_000);
    for (CacheType type : Arrays.asList(
      CacheType.builder().StormTracking(seconds.build()).build(),
      CacheType.builder().StormTracking(seconds.timeUnits(TimeUnits.Seconds).build()).build()
    )) {
      assertSame(type, c -> {
        c.step("PutCacheEntry", put("a", live));
        assertEquals(MISSING, c.step("GetCacheEntry", get("a")));
        c.step("GetCacheEntry", get("a"));
        c.step("GetCacheEntry", get("a"));
        // Putting the refreshed entry ends the refresh; the next caller inside the grace period refreshes again.
        c.step("PutCacheEntry", put("a", live));
        assertEquals(MISSING, c.step("GetCacheEntry", get("a")));
        c.step("GetCacheEntry", get("a"));
        // Outside the grace period: always the entry.
        c.step("PutCacheEntry", put("b", now + 300_000));
        c.step("GetCacheEntry", get("b"));
        c.step("GetCacheEntry", get("b"));
        assertEquals(5, c.hits);
      });
    }
    // The default cache: a 10 second grace period and a 1 second interval, in milliseconds.
    assertSame(
      CacheType.builder().Default(DefaultCache.builder().entryCapacity(5).build()).build(),
      c -> {
        c.step("PutCacheEntry", put("a", now + 5));
        assertEquals(MISSING, c.step("GetCacheEntry", get("a")));
        c.step("GetCacheEntry", get("a"));
        c.step("PutCacheEntry", put("b", live));
        c.step("GetCacheEntry", get("b"));
        c.step("GetCacheEntry", get("b"));
        assertEquals(3, c.hits);
      }
    );
  }

  // With fanOut keys in flight, a caller for a missing key waits, then fails after inFlightTTL;
  // present entries are still returned.
  // The script runs within the one second between in-flight prunes, with 200 ms of slack on each wait.
  @Test
  void stormTrackingFanOut() {
    StormTrackingCache settings = storm(10)
      .entryPruningTailSize(1)
      .gracePeriod(400)
      .graceInterval(200)
      .inFlightTTL(200)
      .fanOut(2)
      .sleepMilli(5)
      .timeUnits(TimeUnits.Milliseconds)
      .build();
    assertSame(
      CacheType.builder().StormTracking(settings).build(),
      c -> {
        c.step("PutCacheEntry", put("p", live));
        assertEquals(MISSING, c.step("GetCacheEntry", get("k1")));
        assertEquals(MISSING, c.step("GetCacheEntry", get("k2")));
        assertEquals(WAIT_EXCEEDED, c.step("GetCacheEntry", get("k3")));
        c.step("GetCacheEntry", get("p"));
        // Still in flight with fanOut reached: even k1 waits.
        assertEquals(WAIT_EXCEEDED, c.step("GetCacheEntry", get("k1")));
        // Deleting a key ends its flight.
        c.step("DeleteCacheEntry", delete("k1"));
        assertEquals(MISSING, c.step("GetCacheEntry", get("k3")));
        c.step("PutCacheEntry", put("k2", live));
        c.step("PutCacheEntry", put("k3", live));
        c.step("GetCacheEntry", get("k2"));
        c.step("GetCacheEntry", get("k3"));
        assertEquals(3, c.hits);
      }
    );
  }

  // An unset entryPruningTailSize (an int left at 0) means 1. ReferenceMpl.toReference would set it to 0,
  // which the reference builder rejects, so the reference input is built without it.
  @Test
  void unsetPruningTailSize() {
    Script prune = c -> {
      c.step("PutCacheEntry", put("e1", expired));
      c.step("PutCacheEntry", put("e2", expired));
      c.step("PutCacheEntry", put("live", live));
      c.getAndClear("live");
      // Pruned with a tail size of 1: "does not exist"; still stored: "past TTL".
      c.getAndClear("e1");
      c.getAndClear("e2");
    };
    for (String kind : new String[] { "SingleThreaded", "MultiThreaded" }) {
      Object referenceKind = ReferenceMpl.build("materialproviders.model." + kind + "Cache", "entryCapacity", 5);
      CacheType nativeType = kind.equals("SingleThreaded")
        ? CacheType.builder().SingleThreaded(SingleThreadedCache.builder().entryCapacity(5).build()).build()
        : CacheType.builder().MultiThreaded(MultiThreadedCache.builder().entryCapacity(5).build()).build();
      assertSame(nativeType, referenceInput(ReferenceMpl.build("materialproviders.model.CacheType", kind, referenceKind)), prune);
    }
    Object referenceStorm = ReferenceMpl.build(
      "materialproviders.model.StormTrackingCache",
      "entryCapacity", 5, "gracePeriod", 10, "graceInterval", 1, "fanOut", 20, "inFlightTTL", 10, "sleepMilli", 20
    );
    assertSame(
      CacheType.builder().StormTracking(storm(5).build()).build(),
      referenceInput(ReferenceMpl.build("materialproviders.model.CacheType", "StormTracking", referenceStorm)),
      prune
    );
  }

  private static Object referenceInput(Object referenceCacheType) {
    return ReferenceMpl.build("materialproviders.model.CreateCryptographicMaterialsCacheInput", "cache", referenceCacheType);
  }

  private String assertCreateSame(CacheType type) {
    CreateCryptographicMaterialsCacheInput input = input(type);
    String expected = ReferenceMpl.outcome(() -> {
      ReferenceMpl.call(reference, "CreateCryptographicMaterialsCache", input);
      return "created";
    });
    String actual = ReferenceMpl.outcome(() -> {
      mpl.CreateCryptographicMaterialsCache(input);
      return "created";
    });
    assertEquals(expected, actual, ReferenceMpl.describe(input));
    return actual;
  }

  /** Runs {@code script} on a new native and a new reference cache of {@code type}; both must give the same outcomes. */
  private void assertSame(CacheType type, Script script) {
    assertSame(type, ReferenceMpl.toReference(input(type)), script);
  }

  /** {@link #assertSame(CacheType, Script)} with the reference input built separately. */
  private void assertSame(CacheType type, Object referenceInput, Script script) {
    Steps expected = new Steps(ReferenceMpl.call(reference, "CreateCryptographicMaterialsCache", referenceInput), null);
    script.run(expected);
    Steps actual = new Steps(null, mpl.CreateCryptographicMaterialsCache(input(type)));
    script.run(actual);
    assertEquals(expected.outcomes, actual.outcomes, ReferenceMpl.describe(type));
  }

  private interface Script {
    void run(Steps c);
  }

  /**
   * Operations on one cache, native or reference, with their outcomes.
   * Each side runs a whole script on its own so that waits on one side do not shift time on the other.
   */
  private static final class Steps {

    final Object referenceCache;
    final ICryptographicMaterialsCache nativeCache;
    final List<String> outcomes = new ArrayList<>();
    int hits;

    Steps(Object referenceCache, ICryptographicMaterialsCache nativeCache) {
      this.referenceCache = referenceCache;
      this.nativeCache = nativeCache;
    }

    String step(String operation, Object input) {
      String outcome = ReferenceMpl.outcome(() ->
        referenceCache != null ? ReferenceMpl.call(referenceCache, operation, input) : runNative(operation, input)
      );
      outcomes.add(operation + " " + ReferenceMpl.describe(input) + " -> " + outcome);
      if (outcome.startsWith("GetCacheEntryOutput")) {
        hits++;
      }
      return outcome;
    }

    // A miss puts a key in flight in a storm-tracking cache; deleting it keeps the next read from waiting.
    void getAndClear(String id) {
      String outcome = step("GetCacheEntry", get(id));
      if (outcome.equals(MISSING) || outcome.equals(EXPIRED)) {
        step("DeleteCacheEntry", delete(id));
      }
    }

    private Object runNative(String operation, Object input) {
      switch (operation) {
        case "PutCacheEntry":
          nativeCache.PutCacheEntry((PutCacheEntryInput) input);
          return null;
        case "GetCacheEntry":
          return nativeCache.GetCacheEntry((GetCacheEntryInput) input);
        case "DeleteCacheEntry":
          nativeCache.DeleteCacheEntry((DeleteCacheEntryInput) input);
          return null;
        case "UpdateUsageMetadata":
          nativeCache.UpdateUsageMetadata((UpdateUsageMetadataInput) input);
          return null;
        default:
          throw new IllegalArgumentException(operation);
      }
    }
  }

  private static CreateCryptographicMaterialsCacheInput input(CacheType type) {
    return CreateCryptographicMaterialsCacheInput.builder().cache(type).build();
  }

  private static CacheType noCache() {
    return CacheType.builder().No(NoCache.builder().build()).build();
  }

  private static StormTrackingCache.Builder storm(int entryCapacity) {
    return StormTrackingCache
      .builder()
      .entryCapacity(entryCapacity)
      .gracePeriod(10)
      .graceInterval(1)
      .fanOut(20)
      .inFlightTTL(10)
      .sleepMilli(20);
  }

  /**
   * Every kind that stores entries, with the given capacity and several pruning tail sizes.
   * The tail size is always set: the reference conversion cannot leave an int unset (see unsetPruningTailSize).
   */
  private static List<CacheType> capacityKinds(int entryCapacity) {
    List<CacheType> kinds = new ArrayList<>();
    kinds.add(CacheType.builder().Default(DefaultCache.builder().entryCapacity(entryCapacity).build()).build());
    for (int tail : new int[] { 1, 2, 3 }) {
      kinds.add(
        CacheType
          .builder()
          .SingleThreaded(SingleThreadedCache.builder().entryCapacity(entryCapacity).entryPruningTailSize(tail).build())
          .build()
      );
      kinds.add(
        CacheType
          .builder()
          .MultiThreaded(MultiThreadedCache.builder().entryCapacity(entryCapacity).entryPruningTailSize(tail).build())
          .build()
      );
      kinds.add(CacheType.builder().StormTracking(storm(entryCapacity).entryPruningTailSize(tail).build()).build());
    }
    kinds.add(
      CacheType.builder().StormTracking(storm(entryCapacity).entryPruningTailSize(1).timeUnits(TimeUnits.Milliseconds).build()).build()
    );
    return kinds;
  }

  private static List<CacheType> allKinds(int entryCapacity) {
    List<CacheType> kinds = capacityKinds(entryCapacity);
    kinds.add(noCache());
    return kinds;
  }

  private static PutCacheEntryInput put(String id, long expiryTime) {
    return put(id, expiryTime, id);
  }

  private static PutCacheEntryInput put(String id, long expiryTime, String keyName) {
    return PutCacheEntryInput
      .builder()
      .identifier(bytes(id))
      .materials(Materials.builder().BranchKey(branchKey(keyName)).build())
      .creationTime(123456789)
      .expiryTime(expiryTime)
      .build();
  }

  private static GetCacheEntryInput get(String id) {
    return GetCacheEntryInput.builder().identifier(bytes(id)).build();
  }

  private static DeleteCacheEntryInput delete(String id) {
    return DeleteCacheEntryInput.builder().identifier(bytes(id)).build();
  }

  private static UpdateUsageMetadataInput usage(String id, int bytesUsed) {
    return UpdateUsageMetadataInput.builder().identifier(bytes(id)).bytesUsed(bytesUsed).build();
  }

  private static BranchKeyMaterials branchKey(String name) {
    return BranchKeyMaterials
      .builder()
      .branchKeyIdentifier("id-" + name)
      .branchKeyVersion("version-" + name)
      .encryptionContext(map("c", name))
      .branchKey(bytes("key-" + name))
      .build();
  }

  private EncryptionMaterials encryptionMaterials() {
    EncryptionMaterials initial = mpl.InitializeEncryptionMaterials(
      InitializeEncryptionMaterialsInput
        .builder()
        .algorithmSuiteId(suite())
        .encryptionContext(map("a", "b"))
        .requiredEncryptionContextKeys(Collections.singletonList("a"))
        .build()
    );
    return initial
      .toBuilder()
      .plaintextDataKey(bytes("0123456789abcdef0123456789abcdef"))
      .encryptedDataKeys(
        Collections.singletonList(
          EncryptedDataKey.builder().keyProviderId("p").keyProviderInfo(bytes("info")).ciphertext(bytes("ciphertext")).build()
        )
      )
      .build();
  }

  private DecryptionMaterials decryptionMaterials() {
    return mpl.InitializeDecryptionMaterials(
      InitializeDecryptionMaterialsInput
        .builder()
        .algorithmSuiteId(suite())
        .encryptionContext(map("a", "b"))
        .requiredEncryptionContextKeys(Collections.emptyList())
        .build()
    );
  }

  private static AlgorithmSuiteId suite() {
    return AlgorithmSuiteId.builder().ESDK(ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY).build();
  }

  private static ByteBuffer bytes(String value) {
    return ByteBuffer.wrap(value.getBytes(StandardCharsets.UTF_8));
  }

  private static Map<String, String> map(String... keysAndValues) {
    Map<String, String> map = new HashMap<>();
    for (int i = 0; i < keysAndValues.length; i += 2) {
      map.put(keysAndValues[i], keysAndValues[i + 1]);
    }
    return map;
  }
}
