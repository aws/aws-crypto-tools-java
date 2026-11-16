// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keyrings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.IntFunction;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.cache.CacheEntry;
import software.amazon.cryptography.materialproviders.cache.CacheKey;
import software.amazon.cryptography.materialproviders.cache.CacheType;
import software.amazon.cryptography.materialproviders.cache.CryptographicMaterialsCache;
import software.amazon.cryptography.materialproviders.cache.DeleteCacheEntryRequest;
import software.amazon.cryptography.materialproviders.cache.DeleteCacheEntryResponse;
import software.amazon.cryptography.materialproviders.cache.GetCacheEntryRequest;
import software.amazon.cryptography.materialproviders.cache.GetCacheEntryResponse;
import software.amazon.cryptography.materialproviders.cache.PutCacheEntryRequest;
import software.amazon.cryptography.materialproviders.cache.PutCacheEntryResponse;
import software.amazon.cryptography.materialproviders.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.materialproviders.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.internal.KeyMaterialsAccess;
import software.amazon.cryptography.materialproviders.internal.cache.CacheClock;

// The native API: builder checks, accessors, exception kinds, and time-dependent cache use on a test clock.
// Behavior against the reference is covered through the test adapter in oldapi.materialproviders.HierarchicalKeyring*Test.
class AwsKmsHierarchicalKeyringTest {

  private static final String REGION = "us-west-2";
  private static final int THREADS = 32;

  private final FakeAws aws = FakeAws.start();
  private final BranchKeyStore store = BranchKeyStore
    .builder()
    .ddbTableName("KeyStoreTable")
    .logicalKeyStoreName("logical")
    .kmsConfiguration(KmsConfiguration.kmsKeyArn(aws.kms().createSymmetricKey(REGION)))
    .kmsClient(aws.kmsClient("native", REGION))
    .ddbClient(aws.dynamoDbClient("native", REGION))
    .build();
  private final String branchKey;

  AwsKmsHierarchicalKeyringTest() {
    store.createKeyStore();
    branchKey = store.createKey().branchKeyIdentifier();
    aws.clearRequests();
  }

  @AfterEach
  void close() {
    aws.close();
  }

  private AwsKmsHierarchicalKeyring.Builder builder() {
    return AwsKmsHierarchicalKeyring.builder().keyStore(store).branchKeyId(branchKey).ttl(Duration.ofSeconds(600));
  }

  //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
  //= type=test
  //# - MUST provide a [KeyStore](../branch-key-store.md)
  //
  //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
  //= type=test
  //# - MUST provide a cache limit TTL
  //
  //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
  //= type=test
  //# - MUST provide either a Branch Key Identifier or a [Branch Key Supplier](#branch-key-supplier)
  @Test
  void builderChecks() {
    assertEquals(
      "Missing value for required field `keyStore`",
      assertThrows(ValidationException.class, () -> AwsKmsHierarchicalKeyring.builder().ttl(Duration.ofSeconds(1)).build()).getMessage()
    );
    assertEquals(
      "Missing value for required field `ttl`",
      assertThrows(ValidationException.class, () -> AwsKmsHierarchicalKeyring.builder().keyStore(store).build()).getMessage()
    );
    assertEquals(
      "`ttl` must be greater than or equal to 0",
      assertThrows(ValidationException.class, () -> builder().ttl(Duration.ofSeconds(-1)).build()).getMessage()
    );
    assertEquals(
      "When creating an AwsKmsHierarchicalKeyring with a StormCache, the ttlSeconds of the KeyRing must be greater than " +
      "the gracePeriod of the StormCache yet the ttlSeconds is 10 and the gracePeriod is 10.",
      assertThrows(ValidationException.class, () -> builder().ttl(Duration.ofSeconds(10)).build()).getMessage()
    );
    assertEquals(
      "Could not UTF-8 Encode Partition ID: Could not encode input to Dafny Bytes.",
      assertThrows(ValidationException.class, () -> builder().partitionId("a\uD800b").build()).getMessage()
    );
    BranchKeyStore badName = BranchKeyStore
      .builder()
      .ddbTableName("KeyStoreTable")
      .logicalKeyStoreName("a\uD800b")
      .kmsConfiguration(KmsConfiguration.kmsKeyArn(aws.kms().createSymmetricKey(REGION)))
      .kmsClient(aws.kmsClient("native", REGION))
      .ddbClient(aws.dynamoDbClient("native", REGION))
      .build();
    assertEquals(
      "Could not UTF-8 Encode Logical Key Store Name: Could not encode input to Dafny Bytes.",
      assertThrows(ValidationException.class, () -> builder().keyStore(badName).build()).getMessage()
    );
    assertEquals(
      "Cannot initialize keyring with both a branchKeyId and BranchKeyIdSupplier.",
      assertThrows(ValidationException.class, () -> builder().branchKeyIdSupplier(request -> GetBranchKeyIdResponse.builder().branchKeyId(branchKey).build()).build()).getMessage()
    );
    assertEquals(
      "Must initialize keyring with either branchKeyId or BranchKeyIdSupplier.",
      assertThrows(ValidationException.class, () -> builder().branchKeyId(null).build()).getMessage()
    );
    assertEquals(
      "`ttl` must be greater than 0",
      assertThrows(ValidationException.class, () -> builder().ttl(Duration.ofSeconds(0)).cache(CacheType.noCache()).build()).getMessage()
    );
    for (Duration fraction : Arrays.asList(Duration.ofMillis(1500), Duration.ofNanos(1), Duration.ofSeconds(5, 1))) {
      assertEquals(
        "`ttl` must be a whole number of seconds",
        assertThrows(ValidationException.class, () -> builder().ttl(fraction).cache(CacheType.noCache()).build()).getMessage()
      );
    }
    assertEquals(
      "Missing value for required field `ttl`",
      assertThrows(ValidationException.class, () -> builder().ttl(null).build()).getMessage()
    );
    builder().ttl(Duration.ofSeconds(1)).cache(CacheType.noCache()).build();
    assertEquals(Duration.ofSeconds(Long.MAX_VALUE), builder().ttl(Duration.ofSeconds(Long.MAX_VALUE)).build().ttl());
  }

  @Test
  void accessors() {
    BranchKeyIdSupplier supplier = request -> GetBranchKeyIdResponse.builder().branchKeyId(branchKey).build();
    CacheType cache = CacheType.multiThreaded(5);
    AwsKmsHierarchicalKeyring configured = builder().branchKeyId(null).branchKeyIdSupplier(supplier).cache(cache).partitionId("p").ttl(Duration.ofSeconds(7)).build();
    assertSame(store, configured.keyStore());
    assertEquals(Optional.empty(), configured.branchKeyId());
    assertSame(supplier, configured.branchKeyIdSupplier().get());
    assertSame(cache, configured.cache().get());
    assertEquals(Optional.of("p"), configured.partitionId());
    assertEquals(Duration.ofSeconds(7), configured.ttl());
    AwsKmsHierarchicalKeyring defaults = builder().build();
    assertEquals(Optional.of(branchKey), defaults.branchKeyId());
    assertFalse(defaults.branchKeyIdSupplier().isPresent());
    assertFalse(defaults.cache().isPresent());
    assertFalse(defaults.partitionId().isPresent());
  }

  @Test
  void theTtlBoundsAnEntrysAgeWhateverItsExpiry() {
    TestClock clock = new TestClock(1_000_999);
    MapCache cache = new MapCache();
    AwsKmsHierarchicalKeyring keyring = builder().ttl(Duration.ofSeconds(5)).cache(CacheType.shared(cache)).clock(clock).build();
    keyring.onEncrypt(OnEncryptRequest.builder().materials(materials()).build());
    assertEquals(2, reads());
    CacheEntry entry = cache.entries.values().iterator().next();
    // Whole seconds, as the Dafny-based keyring's clock.
    assertEquals(Instant.ofEpochSecond(1000), entry.creationTime());
    assertEquals(Instant.ofEpochSecond(1005), entry.expiryTime());
    clock.millis = 1_005_999;
    keyring.onEncrypt(OnEncryptRequest.builder().materials(materials()).build());
    assertEquals(0, reads());
    clock.millis = 1_006_000;
    keyring.onEncrypt(OnEncryptRequest.builder().materials(materials()).build());
    assertEquals(2, reads());
    // An entry created after now (the clock went back) is within the TTL.
    clock.millis = 900_000;
    keyring.onEncrypt(OnEncryptRequest.builder().materials(materials()).build());
    assertEquals(0, reads());
  }

  @Test
  void theExpiryIsCappedAndTheSumMustFitALong() {
    TestClock clock = new TestClock(1_000_000);
    MapCache cache = new MapCache();
    // now = 1000 s: now + ttl = Long.MAX_VALUE - 1 is the largest sum that passes.
    builder().ttl(Duration.ofSeconds(Long.MAX_VALUE - 1001)).cache(CacheType.shared(cache)).clock(clock).build().onEncrypt(OnEncryptRequest.builder().materials(materials()).build());
    assertEquals(Instant.MAX, cache.entries.values().iterator().next().expiryTime());
    AwsKmsHierarchicalKeyring overflow = builder().ttl(Duration.ofSeconds(Long.MAX_VALUE - 1000)).cache(CacheType.shared(new MapCache())).clock(clock).build();
    assertEquals("INT64 Overflow when putting cache entry.", assertThrows(ValidationException.class, () -> overflow.onEncrypt(OnEncryptRequest.builder().materials(materials()).build())).getMessage());
  }

  @Test
  void cacheEntriesThatAreNotBranchKeys() {
    MapCache cache = new MapCache();
    AwsKmsHierarchicalKeyring keyring = builder().cache(CacheType.shared(cache)).build();
    keyring.onEncrypt(OnEncryptRequest.builder().materials(materials()).build());
    CacheKey key = cache.entries.keySet().iterator().next();
    cache.entries.put(
      key,
      CacheEntry.of(KeyMaterialsAccess.beaconKey(branchKey, EncryptionContext.empty(), null, new HashMap<>()), Instant.now(), Instant.now())
    );
    assertEquals("Invalid Material Type.", assertThrows(InvalidMaterialsException.class, () -> keyring.onEncrypt(OnEncryptRequest.builder().materials(materials()).build())).getMessage());
  }

  @Test
  void callerFailuresPropagateUnchanged() {
    IllegalStateException failure = new IllegalStateException("cache failed");
    CryptographicMaterialsCache failing = new MapCache() {
      @Override
      public GetCacheEntryResponse getCacheEntry(GetCacheEntryRequest request) {
        throw failure;
      }
    };
    assertSame(failure, assertThrows(IllegalStateException.class, () -> builder().cache(CacheType.shared(failing)).build().onEncrypt(OnEncryptRequest.builder().materials(materials()).build())));
    RuntimeException supplierFailure = new RuntimeException("supplier failed");
    AwsKmsHierarchicalKeyring throwing = builder().branchKeyId(null).branchKeyIdSupplier(request -> {
      throw supplierFailure;
    }).build();
    assertSame(supplierFailure, assertThrows(RuntimeException.class, () -> throwing.onEncrypt(OnEncryptRequest.builder().materials(materials()).build())));
  }

  @Test
  void aSupplierReturningNullFails() {
    AwsKmsHierarchicalKeyring nullId = builder().branchKeyId(null).branchKeyIdSupplier(request -> null).build();
    assertEquals(
      "BranchKeyIdSupplier returned no branch key id.",
      assertThrows(ValidationException.class, () -> nullId.onEncrypt(OnEncryptRequest.builder().materials(materials()).build())).getMessage()
    );
    DecryptionMaterials start = DecryptionMaterials.builder(EsdkAlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).encryptionContext(EncryptionContext.of("a", "b")).build();
    assertEquals(
      "BranchKeyIdSupplier returned no branch key id.",
      assertThrows(ValidationException.class, () -> nullId.onDecrypt(OnDecryptRequest.builder().materials(start).encryptedDataKeys(Collections.emptyList()).build())).getMessage()
    );
    // A response cannot hold a null id: the supplier's own call fails, with the same exception kind.
    AwsKmsHierarchicalKeyring nullInResponse = builder().branchKeyId(null).branchKeyIdSupplier(request -> GetBranchKeyIdResponse.builder().branchKeyId(null).build()).build();
    assertEquals(
      "Missing value for required field `branchKeyId`",
      assertThrows(ValidationException.class, () -> nullInResponse.onEncrypt(OnEncryptRequest.builder().materials(materials()).build())).getMessage()
    );
  }

  @Test
  void decryptFailureKinds() {
    AwsKmsHierarchicalKeyring keyring = builder().build();
    EncryptionMaterials encrypted = keyring.onEncrypt(OnEncryptRequest.builder().materials(materials()).build()).materials();
    DecryptionMaterials start = DecryptionMaterials.builder(EsdkAlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).encryptionContext(EncryptionContext.of("a", "b")).build();
    NoMatchingDataKeyException none = assertThrows(NoMatchingDataKeyException.class, () -> keyring.onDecrypt(OnDecryptRequest.builder().materials(start).encryptedDataKeys(Collections.emptyList()).build()));
    assertTrue(none.failures().isEmpty());
    EncryptedDataKey edk = encrypted.encryptedDataKeys().get(0);
    byte[] ciphertext = edk.ciphertext();
    ciphertext[ciphertext.length - 1] ^= 1;
    List<EncryptedDataKey> tampered = new ArrayList<>();
    tampered.add(EncryptedDataKey.builder()
        .keyProviderId(edk.keyProviderId())
        .keyProviderInfo(edk.keyProviderInfo())
        .ciphertext(ciphertext)
        .build());
    tampered.add(EncryptedDataKey.builder()
        .keyProviderId(edk.keyProviderId())
        .keyProviderInfo(edk.keyProviderInfo())
        .ciphertext(new byte[3])
        .build());
    NoMatchingDataKeyException failed = assertThrows(NoMatchingDataKeyException.class, () -> keyring.onDecrypt(OnDecryptRequest.builder().materials(start).encryptedDataKeys(tampered).build()));
    assertEquals(2, failed.failures().size());
    assertEquals("Received EDK Ciphertext of incorrect length.", failed.failures().get(1).getMessage());
    assertTrue(keyring.onDecrypt(OnDecryptRequest.builder().materials(start).encryptedDataKeys(encrypted.encryptedDataKeys()).build()).materials().plaintextDataKey().get().contentEquals(encrypted.plaintextDataKey().get()));
  }

  @Test
  void concurrentCallsOnTheDefaultCacheReadTheKeyStoreOnce() throws Exception {
    AwsKmsHierarchicalKeyring keyring = builder().build();
    assertConcurrentReads(keyring, 1);
  }

  @Test
  void concurrentMissesOnAMultiThreadedCacheEachReadTheKeyStore() throws Exception {
    // As in Dafny, only a storm-tracking cache makes concurrent misses wait for one read; with any other cache each
    // caller that misses reads the key store. The cache here holds every lookup until all callers have missed.
    CryptographicMaterialsCache multiThreaded = CryptographicMaterialsCache.create(CacheType.multiThreaded(10));
    CyclicBarrier allLookedUp = new CyclicBarrier(THREADS);
    CryptographicMaterialsCache missTogether = new CryptographicMaterialsCache() {
      @Override
      public GetCacheEntryResponse getCacheEntry(GetCacheEntryRequest request) {
        GetCacheEntryResponse response = multiThreaded.getCacheEntry(request);
        await(allLookedUp);
        return response;
      }

      @Override
      public PutCacheEntryResponse putCacheEntry(PutCacheEntryRequest request) {
        return multiThreaded.putCacheEntry(request);
      }

      @Override
      public DeleteCacheEntryResponse deleteCacheEntry(DeleteCacheEntryRequest request) {
        return multiThreaded.deleteCacheEntry(request);
      }
    };
    assertConcurrentReads(builder().cache(CacheType.shared(missTogether)).build(), THREADS);
  }

  // THREADS concurrent encryptions, then THREADS concurrent decryptions of their results, each phase making
  // expectedReads key store reads.
  private void assertConcurrentReads(AwsKmsHierarchicalKeyring keyring, int expectedReads) throws Exception {
    List<EncryptionMaterials> encrypted = concurrently(i -> keyring.onEncrypt(OnEncryptRequest.builder().materials(materials()).build()).materials());
    assertEquals(2 * expectedReads, reads());
    DecryptionMaterials start = DecryptionMaterials.builder(EsdkAlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).encryptionContext(EncryptionContext.of("a", "b")).build();
    List<DecryptionMaterials> decrypted = concurrently(i -> keyring.onDecrypt(OnDecryptRequest.builder().materials(start).encryptedDataKeys(encrypted.get(i).encryptedDataKeys()).build()).materials());
    assertEquals(2 * expectedReads, reads());
    for (int i = 0; i < THREADS; i++) {
      assertTrue(decrypted.get(i).plaintextDataKey().get().contentEquals(encrypted.get(i).plaintextDataKey().get()));
    }
  }

  // Runs call(0) .. call(THREADS - 1) on THREADS threads released together; returns the results in order.
  private static <T> List<T> concurrently(IntFunction<T> call) throws Exception {
    ExecutorService executor = Executors.newFixedThreadPool(THREADS);
    try {
      CyclicBarrier start = new CyclicBarrier(THREADS);
      List<Future<T>> futures = new ArrayList<>();
      for (int i = 0; i < THREADS; i++) {
        int index = i;
        futures.add(
          executor.submit(() -> {
            await(start);
            return call.apply(index);
          })
        );
      }
      List<T> results = new ArrayList<>();
      for (Future<T> future : futures) {
        results.add(future.get(30, TimeUnit.SECONDS));
      }
      return results;
    } finally {
      executor.shutdownNow();
    }
  }

  private static void await(CyclicBarrier barrier) {
    try {
      barrier.await(10, TimeUnit.SECONDS);
    } catch (InterruptedException | BrokenBarrierException | TimeoutException e) {
      throw new IllegalStateException(e);
    }
  }

  private static EncryptionMaterials materials() {
    return EncryptionMaterials.builder(EsdkAlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).encryptionContext(EncryptionContext.of("a", "b")).build();
  }

  // Key store reads since the last call; each is a DynamoDB GetItem and a KMS Decrypt.
  private int reads() {
    int count = aws.requests("native").size();
    aws.clearRequests();
    return count;
  }

  private static final class TestClock implements CacheClock {

    long millis;

    TestClock(long millis) {
      this.millis = millis;
    }

    @Override
    public long wallMillis() {
      return millis;
    }

    @Override
    public long monotonicMillis() {
      return millis;
    }
  }

  // Keeps every entry regardless of its expiry, so only the keyring's TTL check decides.
  private static class MapCache implements CryptographicMaterialsCache {

    final Map<CacheKey, CacheEntry> entries = new HashMap<>();

    @Override
    public GetCacheEntryResponse getCacheEntry(GetCacheEntryRequest request) {
      return GetCacheEntryResponse.builder().entry(entries.get(request.key())).build();
    }

    @Override
    public PutCacheEntryResponse putCacheEntry(PutCacheEntryRequest request) {
      entries.put(request.key(), request.entry());
      return PutCacheEntryResponse.builder().build();
    }

    @Override
    public DeleteCacheEntryResponse deleteCacheEntry(DeleteCacheEntryRequest request) {
      entries.remove(request.key());
      return DeleteCacheEntryResponse.builder().build();
    }
  }
}
