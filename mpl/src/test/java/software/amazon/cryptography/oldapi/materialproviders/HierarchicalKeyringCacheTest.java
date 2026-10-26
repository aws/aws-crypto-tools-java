// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.LOGICAL_NAME;
import static software.amazon.cryptography.oldapi.materialproviders.KeyringTests.*;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.oldapi.keystore.model.BeaconKeyMaterials;
import software.amazon.cryptography.oldapi.keystore.model.BranchKeyMaterials;
import software.amazon.cryptography.oldapi.materialproviders.HierarchicalHarness.CacheScript;
import software.amazon.cryptography.oldapi.materialproviders.HierarchicalHarness.CustomerCache;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Outcomes;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Pair;
import software.amazon.cryptography.oldapi.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.AwsCryptographicMaterialProvidersException;
import software.amazon.cryptography.oldapi.materialproviders.model.CacheType;
import software.amazon.cryptography.oldapi.materialproviders.model.DefaultCache;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.EntryAlreadyExists;
import software.amazon.cryptography.oldapi.materialproviders.model.GetCacheEntryInput;
import software.amazon.cryptography.oldapi.materialproviders.model.GetCacheEntryOutput;
import software.amazon.cryptography.oldapi.materialproviders.model.Materials;
import software.amazon.cryptography.oldapi.materialproviders.model.MultiThreadedCache;
import software.amazon.cryptography.oldapi.materialproviders.model.NoCache;
import software.amazon.cryptography.oldapi.materialproviders.model.OnDecryptInput;
import software.amazon.cryptography.oldapi.materialproviders.model.PutCacheEntryInput;
import software.amazon.cryptography.oldapi.materialproviders.model.SingleThreadedCache;
import software.amazon.cryptography.oldapi.materialproviders.model.StormTrackingCache;
import software.amazon.cryptography.oldapi.materialproviders.model.TimeUnits;

/**
 * Differential tests of the hierarchical keyring's cache use, observed through the keyring:
 * the key store requests each side makes, shared caches and partition ids,
 * and a caller's cache answering with anything the old cache interface allows.
 */
class HierarchicalKeyringCacheTest {

  private static final String PARTITION = "partition";
  private static final Pattern EXPIRY = Pattern.compile("expiryTime=(\\d+)");

  private final HierarchicalHarness h = new HierarchicalHarness();
  private final String branchKey = h.createBranchKey();
  private final String version = h.active(branchKey).branchKeyVersion();
  private final Outcomes outcomes = new Outcomes();
  private final AlgorithmSuiteId suite = allSuites().get(0);

  HierarchicalKeyringCacheTest() {
    h.aws.clearRequests();
  }

  @AfterEach
  void close() {
    h.close();
  }

  private static CacheType multiThreaded() {
    return CacheType.builder().MultiThreaded(MultiThreadedCache.builder().entryCapacity(10).entryPruningTailSize(1).build()).build();
  }

  private static CacheType storm(TimeUnits units, int gracePeriod, int graceInterval, int inFlightTTL) {
    return storm(units, gracePeriod, graceInterval, inFlightTTL, 20);
  }

  private static CacheType storm(TimeUnits units, int gracePeriod, int graceInterval, int inFlightTTL, int fanOut) {
    return CacheType
      .builder()
      .StormTracking(
        StormTrackingCache
          .builder()
          .entryCapacity(10)
          .entryPruningTailSize(1)
          .gracePeriod(gracePeriod)
          .graceInterval(graceInterval)
          .fanOut(fanOut)
          .inFlightTTL(inFlightTTL)
          .sleepMilli(10)
          .timeUnits(units)
          .build()
      )
      .build();
  }

  @Test
  void cacheHitsAvoidTheKeyStore() {
    List<CacheType> caches = Arrays.asList(
      null,
      CacheType.builder().Default(DefaultCache.builder().entryCapacity(10).build()).build(),
      CacheType.builder().No(NoCache.builder().build()).build(),
      CacheType.builder().SingleThreaded(SingleThreadedCache.builder().entryCapacity(10).entryPruningTailSize(1).build()).build(),
      multiThreaded(),
      storm(TimeUnits.Seconds, 60, 1, 10),
      storm(TimeUnits.Milliseconds, 60000, 1000, 10000),
      h.sharedBuiltIn(multiThreaded()),
      h.sharedBuiltIn(storm(TimeUnits.Seconds, 60, 1, 10))
    );
    for (CacheType cache : caches) {
      Pair keyring = h.keyrings(h.input(branchKey).cache(cache).build());
      // Each side: two encryptions, two decryptions of its first encrypted data key, and one of the other side's.
      EncryptionMaterials nativeFirst = keyring.nativeEncrypt(encryptionMaterials(suite, map(), false));
      keyring.nativeEncrypt(encryptionMaterials(suite, map(), false));
      EncryptionMaterials referenceFirst = keyring.referenceEncrypt(encryptionMaterials(suite, map(), false));
      keyring.referenceEncrypt(encryptionMaterials(suite, map(), false));
      for (int i = 0; i < 2; i++) {
        keyring.assertSameDecrypt(outcomes, decryptionMaterials(nativeFirst), nativeFirst.encryptedDataKeys(), "native EDK");
      }
      keyring.assertSameDecrypt(outcomes, decryptionMaterials(referenceFirst), referenceFirst.encryptedDataKeys(), "reference EDK");
      List<String> requests = h.sameRequests();
      boolean caching = cache == null || cache.No() == null;
      // Every key store read is one GetItem and one KMS Decrypt.
      assertEquals(caching ? 4 : 10, requests.size(), String.valueOf(cache) + requests);
    }
  }

  @Test
  void partitionIdsAndLogicalNamesSeparateSharedEntries() {
    CacheType shared = h.sharedBuiltIn(multiThreaded());
    Pair first = h.keyrings(h.input(branchKey).cache(shared).partitionId(PARTITION).build());
    Pair samePartition = h.keyrings(h.input(branchKey).cache(shared).partitionId(PARTITION).build());
    Pair otherPartition = h.keyrings(h.input(branchKey).cache(shared).partitionId("other").build());
    Pair randomPartition = h.keyrings(h.input(branchKey).cache(shared).build());
    Pair otherRandomPartition = h.keyrings(h.input(branchKey).cache(shared).build());
    Pair otherName = h.keyrings(h.input(branchKey).cache(shared).partitionId(PARTITION).keyStore(h.storeNamed("other-name")).build());
    EncryptionMaterials encrypted = encryptBoth(first, 2);
    encryptBoth(samePartition, 0);
    encryptBoth(otherPartition, 2);
    encryptBoth(randomPartition, 2);
    // Without a partition id each keyring gets its own random one.
    encryptBoth(otherRandomPartition, 2);
    // A miss: the other store reads the branch key, and KMS refuses it under the other logical name.
    String failed = sameEncrypt(otherName, encryptionMaterials(suite, map(), false));
    assertTrue(failed.contains("InvalidCiphertextException"), failed);
    assertEquals(2, h.sameRequests().size());
    // Decryption entries are separate from encryption entries, and shared the same way.
    decryptBoth(first, encrypted, 2);
    decryptBoth(samePartition, encrypted, 0);
    decryptBoth(otherPartition, encrypted, 2);
  }

  private EncryptionMaterials encryptBoth(Pair keyring, int expectedRequests) {
    EncryptionMaterials encrypted = keyring.nativeEncrypt(encryptionMaterials(suite, map(), false));
    keyring.referenceEncrypt(encryptionMaterials(suite, map(), false));
    assertEquals(expectedRequests, h.sameRequests().size());
    return encrypted;
  }

  private void decryptBoth(Pair keyring, EncryptionMaterials encrypted, int expectedRequests) {
    String decrypted = keyring.assertSameDecrypt(outcomes, decryptionMaterials(encrypted), encrypted.encryptedDataKeys(), "");
    assertEquals(ReferenceMpl.describe(expectedDecryption(encrypted)), decrypted);
    assertEquals(expectedRequests, h.sameRequests().size());
  }

  @Test
  void aSharedStormCacheMakesTheKeyringWaitForAnotherFetch() {
    String otherBranchKey = h.createBranchKey();
    // The cache forgets a flight older than inFlightTTL only when it prunes, at most once a second, starting with the
    // keyring's first lookup. At 1500 ms the wait ends between two prunes, so a pause shorter than 500 ms (before the
    // keyring's lookup, or while it waits) cannot end the flight early; a multiple of 1000 ms would end it at the deadline.
    CacheType shared = h.sharedBuiltIn(storm(TimeUnits.Milliseconds, 2000, 100, 1500, 1));
    ICryptographicMaterialsCache nativeCache = shared.Shared();
    Object referenceCache = ReferenceMpl.toReference(nativeCache);
    Pair keyring = h.keyrings(h.input(branchKey).cache(shared).partitionId(PARTITION).build());
    // Its own cache: the flight the decryption leaves behind would make any other key wait at fanOut 1.
    CacheType otherShared = h.sharedBuiltIn(storm(TimeUnits.Milliseconds, 2000, 100, 1500, 1));
    ICryptographicMaterialsCache otherNativeCache = otherShared.Shared();
    Object otherReferenceCache = ReferenceMpl.toReference(otherNativeCache);
    Pair otherKeyring = h.keyrings(h.input(otherBranchKey).cache(otherShared).partitionId(PARTITION).build());
    // The keyring's entry is under the identifier the spec gives.
    keyring.nativeEncrypt(encryptionMaterials(suite, map(), false));
    keyring.referenceEncrypt(encryptionMaterials(suite, map(), false));
    assertTrue(get(nativeCache, referenceCache, HierarchicalHarness.cacheId(PARTITION, LOGICAL_NAME, branchKey, null)).startsWith("GetCacheEntryOutput"));
    // Another caller misses first, so one fetch is in flight, the fanOut; the keyring waits until inFlightTTL and fails.
    // Each side misses right before its own keyring call: a flight ends inFlightTTL after it starts.
    EncryptionMaterials encrypted = h
      .keyrings(h.input(branchKey).cache(CacheType.builder().No(NoCache.builder().build()).build()).build())
      .nativeEncrypt(encryptionMaterials(suite, map(), false));
    GetCacheEntryInput decryptEntry = GetCacheEntryInput.builder().identifier(HierarchicalHarness.cacheId(PARTITION, LOGICAL_NAME, branchKey, version)).build();
    OnDecryptInput decrypt = decryptInput(decryptionMaterials(encrypted), encrypted.encryptedDataKeys());
    String nativeOutcome = ReferenceMpl.outcome(() -> {
      assertTrue(ReferenceMpl.outcome(() -> nativeCache.GetCacheEntry(decryptEntry)).contains("EntryDoesNotExist"));
      return keyring.nativeKeyring.OnDecrypt(decrypt);
    });
    String referenceOutcome = ReferenceMpl.outcome(() -> {
      assertTrue(ReferenceMpl.outcome(() -> ReferenceMpl.call(referenceCache, "GetCacheEntry", decryptEntry)).contains("EntryDoesNotExist"));
      return ReferenceMpl.call(keyring.referenceKeyring, "OnDecrypt", decrypt);
    });
    assertEquals(referenceOutcome, nativeOutcome);
    assertTrue(nativeOutcome.contains("InFlightTTLExceeded"), nativeOutcome);
    GetCacheEntryInput encryptEntry = GetCacheEntryInput.builder().identifier(HierarchicalHarness.cacheId(PARTITION, LOGICAL_NAME, otherBranchKey, null)).build();
    nativeOutcome = ReferenceMpl.outcome(() -> {
      assertTrue(ReferenceMpl.outcome(() -> otherNativeCache.GetCacheEntry(encryptEntry)).contains("EntryDoesNotExist"));
      return otherKeyring.nativeEncrypt(encryptionMaterials(suite, map(), false));
    });
    referenceOutcome = ReferenceMpl.outcome(() -> {
      assertTrue(ReferenceMpl.outcome(() -> ReferenceMpl.call(otherReferenceCache, "GetCacheEntry", encryptEntry)).contains("EntryDoesNotExist"));
      return otherKeyring.referenceEncrypt(encryptionMaterials(suite, map(), false));
    });
    assertEquals(referenceOutcome, nativeOutcome);
    assertTrue(nativeOutcome.contains("InFlightTTLExceeded"), nativeOutcome);
  }

  // GetCacheEntry on each side's cache: the same outcome, with entry times masked.
  private static String get(ICryptographicMaterialsCache nativeCache, Object referenceCache, ByteBuffer identifier) {
    GetCacheEntryInput get = GetCacheEntryInput.builder().identifier(identifier).build();
    String nativeOutcome = ReferenceMpl.outcome(() -> nativeCache.GetCacheEntry(get)).replaceAll("(creationTime|expiryTime)=\\d+", "$1");
    String referenceOutcome = ReferenceMpl.outcome(() -> ReferenceMpl.call(referenceCache, "GetCacheEntry", get)).replaceAll("(creationTime|expiryTime)=\\d+", "$1");
    assertEquals(referenceOutcome, nativeOutcome);
    return nativeOutcome;
  }

  @Test
  void aSharedBuiltInCacheHoldingOtherMaterials() {
    CacheType shared = h.sharedBuiltIn(multiThreaded());
    ICryptographicMaterialsCache nativeCache = shared.Shared();
    Object referenceCache = ReferenceMpl.toReference(nativeCache);
    Pair keyring = h.keyrings(h.input(branchKey).cache(shared).partitionId(PARTITION).build());
    ByteBuffer encryptId = HierarchicalHarness.cacheId(PARTITION, LOGICAL_NAME, branchKey, null);
    long now = Instant.now().getEpochSecond();
    Materials encryption = Materials.builder().Encryption(encryptionMaterials(suite, map(), false)).build();
    // Within the keyring's TTL a cached entry that is not a branch key fails; past it the keyring reads the key store and replaces it.
    for (long creationTime : new long[] { now, now - 1000 }) {
      PutCacheEntryInput put = PutCacheEntryInput
        .builder()
        .identifier(encryptId)
        .materials(encryption)
        .creationTime(creationTime)
        .expiryTime(now + 1000)
        .build();
      nativeCache.PutCacheEntry(put);
      ReferenceMpl.call(referenceCache, "PutCacheEntry", put);
      String outcome = keyring.assertSameEncrypt(outcomes, encryptionMaterials(suite, map(), false), "creation " + creationTime, 0);
      assertEquals(creationTime == now, outcome.contains("Invalid Material Type."), outcome);
    }
    assertEquals(2, h.sameRequests().size());
    // The keyring's own entry replaced it.
    keyring.assertSameEncrypt(outcomes, encryptionMaterials(suite, map(), false), "replaced", 0);
    assertEquals(0, h.sameRequests().size());
  }

  @Test
  void customerCaches() {
    EncryptionMaterials encrypted = h
      .keyrings(h.input(branchKey).cache(CacheType.builder().No(NoCache.builder().build()).build()).build())
      .nativeEncrypt(encryptionMaterials(suite, map("a", "b"), false));
    BranchKeyMaterials active = h.active(branchKey);
    h.aws.clearRequests();
    long now = Instant.now().getEpochSecond();
    List<CacheScript> scripts = new ArrayList<>();
    scripts.add(new CacheScript() {});
    scripts.add(getAnswers(input -> {
      throw new IllegalStateException("cache failed");
    }));
    scripts.add(getAnswers(input -> {
      throw AwsCryptographicMaterialProvidersException.builder().message("modeled failure").build();
    }));
    scripts.add(getAnswers(input -> null));
    // Entries that are not branch keys fail while within the TTL, and are read again past it.
    Materials encryption = Materials.builder().Encryption(encryptionMaterials(suite, map(), false)).build();
    Materials decryption = Materials.builder().Decryption(decryptionMaterials(encrypted)).build();
    Materials beacon = Materials
      .builder()
      .BeaconKey(BeaconKeyMaterials.builder().beaconKeyIdentifier(branchKey).encryptionContext(map()).beaconKey(ByteBuffer.wrap(bytes(32, 1))).build())
      .build();
    for (Materials materials : Arrays.asList(encryption, decryption, beacon)) {
      scripts.add(entry(materials, now));
      scripts.add(entry(materials, now - 1000));
    }
    // Branch keys the key store would not return: other lengths and versions, and values that do not convert.
    for (int length : new int[] { 31, 32, 48, 66 }) {
      scripts.add(entry(branchKeyMaterials(version, map(), length), now));
    }
    for (String otherVersion : Arrays.asList("not-a-uuid", "1-1-1-1-1", "a\uD800b", "")) {
      scripts.add(entry(branchKeyMaterials(otherVersion, map(), 32), now));
    }
    scripts.add(entry(branchKeyMaterials(version, map("k", "a\uD800b"), 32), now));
    // The real branch key: under its own version it decrypts; under another the AAD has that version, which the EDK does not.
    scripts.add(entry(Materials.builder().BranchKey(active).build(), now));
    scripts.add(entry(Materials.builder().BranchKey(active.toBuilder().branchKeyVersion("1-1-1-1-1").build()).build(), now));
    // The keyring's TTL bounds the age of an entry, whatever its expiry.
    scripts.add(entry(branchKeyMaterials(version, map(), 32), now - 599));
    scripts.add(entry(branchKeyMaterials(version, map(), 32), now - 700));
    scripts.add(entry(branchKeyMaterials(version, map(), 32), Long.MAX_VALUE));
    // A failed put: an existing entry is not a failure.
    scripts.add(putFails(EntryAlreadyExists.builder().message("exists").build()));
    scripts.add(putFails(new IllegalStateException("put failed")));
    scripts.add(putFails(AwsCryptographicMaterialProvidersException.builder().message("modeled put failure").build()));

    for (CacheScript script : scripts) {
      CustomerCache cache = new CustomerCache(script);
      Pair keyring = h.keyrings(h.input(branchKey).cache(cache.cacheType()).partitionId(PARTITION).build());
      for (int i = 0; i < 2; i++) {
        String nativeOutcome = ReferenceMpl.outcome(() -> masked(keyring.nativeEncrypt(encryptionMaterials(suite, map(), false)), false, 0));
        String referenceOutcome = ReferenceMpl.outcome(() -> masked(keyring.referenceEncrypt(encryptionMaterials(suite, map(), false)), false, 0));
        assertEquals(referenceOutcome, nativeOutcome);
        outcomes.record("OnEncrypt", nativeOutcome);
        keyring.assertSameDecrypt(outcomes, decryptionMaterials(encrypted), encrypted.encryptedDataKeys(), "");
      }
      cache.assertSameReceived();
      h.sameRequests();
    }
    outcomes.assertBothSeen("OnEncrypt");
    outcomes.assertBothSeen("OnDecrypt");
  }

  @Test
  void aCacheEntryForAHugeTtlExpiresAtTheInstantLimit() {
    long ttl = Long.MAX_VALUE / 2;
    CustomerCache cache = new CustomerCache(new CacheScript() {});
    Pair keyring = h.keyrings(h.input(branchKey).ttlSeconds(ttl).cache(cache.cacheType()).partitionId(PARTITION).build());
    keyring.nativeEncrypt(encryptionMaterials(suite, map(), false));
    keyring.referenceEncrypt(encryptionMaterials(suite, map(), false));
    List<Long> nativeExpiries = expiries(cache.nativeReceived);
    List<Long> referenceExpiries = expiries(cache.referenceReceived);
    cache.assertSameReceived();
    // Dafny stored now + ttlSeconds; a native CacheEntry expiry saturates at Instant.MAX.
    assertEquals(Collections.singletonList(Instant.MAX.getEpochSecond()), nativeExpiries);
    assertEquals(1, referenceExpiries.size());
    assertTrue(referenceExpiries.get(0) > ttl, referenceExpiries.toString());
    // Past the int64 limit both sides fail after reading the key store.
    Pair overflow = h.keyrings(h.input(branchKey).ttlSeconds(Long.MAX_VALUE).cache(multiThreaded()).build());
    String failed = overflow.assertSameEncrypt(outcomes, encryptionMaterials(suite, map(), false), "overflow", 0);
    assertTrue(failed.contains("INT64 Overflow when putting cache entry."), failed);
  }

  @Test
  void nowPlusTheTtlMustBeBelowTheInt64Maximum() {
    for (long margin : new long[] { 0, 1 }) {
      String outcome = null;
      // Both sides read the clock in whole seconds; an attempt counts only if the second did not change during it.
      while (outcome == null) {
        long now = Instant.now().getEpochSecond();
        Pair keyring = h.keyrings(h.input(branchKey).ttlSeconds(Long.MAX_VALUE - now - margin).cache(multiThreaded()).build());
        String nativeOutcome = ReferenceMpl.outcome(() -> masked(keyring.nativeEncrypt(encryptionMaterials(suite, map(), false)), false, 0));
        String referenceOutcome = ReferenceMpl.outcome(() -> masked(keyring.referenceEncrypt(encryptionMaterials(suite, map(), false)), false, 0));
        if (Instant.now().getEpochSecond() == now) {
          assertEquals(referenceOutcome, nativeOutcome, "margin " + margin);
          outcome = outcomes.record("OnEncrypt", nativeOutcome);
        }
      }
      assertEquals(margin == 0, outcome.contains("INT64 Overflow when putting cache entry."), outcome);
    }
    outcomes.assertBothSeen("OnEncrypt");
  }

  private static List<Long> expiries(List<String> calls) {
    List<Long> expiries = new ArrayList<>();
    for (String call : calls) {
      Matcher matcher = EXPIRY.matcher(call);
      if (call.startsWith("PutCacheEntry") && matcher.find()) {
        expiries.add(Long.parseLong(matcher.group(1)));
      }
    }
    return expiries;
  }

  private static CacheScript getAnswers(Function<GetCacheEntryInput, GetCacheEntryOutput> answer) {
    return new CacheScript() {
      @Override
      public GetCacheEntryOutput get(GetCacheEntryInput input, Map<String, GetCacheEntryOutput> stored) {
        return answer.apply(input);
      }
    };
  }

  private static CacheScript entry(Materials materials, long creationTime) {
    return getAnswers(input ->
      GetCacheEntryOutput.builder().materials(materials).creationTime(creationTime).expiryTime(creationTime).messagesUsed(0).bytesUsed(0).build()
    );
  }

  private Materials branchKeyMaterials(String branchKeyVersion, Map<String, String> encryptionContext, int length) {
    return Materials
      .builder()
      .BranchKey(
        BranchKeyMaterials
          .builder()
          .branchKeyIdentifier(branchKey)
          .branchKeyVersion(branchKeyVersion)
          .encryptionContext(encryptionContext)
          .branchKey(ByteBuffer.wrap(bytes(length, 7)))
          .build()
      )
      .build();
  }

  private static CacheScript putFails(RuntimeException failure) {
    return new CacheScript() {
      @Override
      public void put(PutCacheEntryInput input, Map<String, GetCacheEntryOutput> stored) {
        throw failure;
      }
    };
  }

  // An outcome with request ids masked: each side's AWS calls get their own.
  private String sameEncrypt(Pair keyring, EncryptionMaterials materials) {
    String expected = KeyStoreHarness.outcome(() -> masked(keyring.referenceEncrypt(materials), false, 0));
    String actual = KeyStoreHarness.outcome(() -> masked(keyring.nativeEncrypt(materials), false, 0));
    assertEquals(expected, actual);
    return outcomes.record("OnEncrypt", actual);
  }
}
