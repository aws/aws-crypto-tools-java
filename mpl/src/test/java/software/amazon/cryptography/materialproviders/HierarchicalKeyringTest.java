// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.materialproviders.HierarchicalHarness.PROVIDER_ID;
import static software.amazon.cryptography.materialproviders.HierarchicalHarness.id;
import static software.amazon.cryptography.materialproviders.HierarchicalHarness.uuidBytes;
import static software.amazon.cryptography.materialproviders.KeyringTests.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.LongFunction;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.VersionKeyInput;
import software.amazon.cryptography.materialproviders.HierarchicalHarness.Supplier;
import software.amazon.cryptography.materialproviders.KeyringTests.Outcomes;
import software.amazon.cryptography.materialproviders.KeyringTests.Pair;
import software.amazon.cryptography.materialproviders.fakeaws.ServiceError;
import software.amazon.cryptography.materialproviders.internal.Convert;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.AwsCryptographicMaterialProvidersException;
import software.amazon.cryptography.materialproviders.model.CacheType;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsHierarchicalKeyringInput;
import software.amazon.cryptography.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.model.DefaultCache;
import software.amazon.cryptography.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.model.MultiThreadedCache;
import software.amazon.cryptography.materialproviders.model.NoCache;
import software.amazon.cryptography.materialproviders.model.SingleThreadedCache;
import software.amazon.cryptography.materialproviders.model.StormTrackingCache;
import software.amazon.cryptography.materialproviders.model.TimeUnits;
import software.amazon.cryptography.mpl.keyrings.AwsKmsHierarchicalKeyring;

/**
 * Differential tests of the hierarchical keyring against the published Dafny-based MPL:
 * creation checks, encryption and decryption for every suite, encrypted data key layout, and failures.
 * Both sides read branch keys from one fake key store table, so they wrap under the same keys.
 * Encryption is randomized (salt, IV, data key), so each side decrypts both sides' encrypted data keys.
 */
class HierarchicalKeyringTest {

  private final HierarchicalHarness h = new HierarchicalHarness();
  private final String branchKey = h.createBranchKey();
  private final String otherBranchKey = h.createBranchKey();
  private final Outcomes outcomes = new Outcomes();

  @AfterEach
  void close() {
    h.close();
  }

  @Test
  void create() {
    List<CreateAwsKmsHierarchicalKeyringInput> inputs = new ArrayList<>();
    List<String> zeroTtlReference = new ArrayList<>();
    // No cache: checked against the default storm-tracking grace period, 10 seconds.
    for (long ttl : new long[] { 0, 1, 9, 10, 11, 600, Long.MAX_VALUE }) {
      inputs.add(h.input(branchKey).ttlSeconds(ttl).build());
    }
    // These cache types are not checked against the TTL.
    List<CacheType> unchecked = Arrays.asList(
      CacheType.builder().Default(DefaultCache.builder().entryCapacity(1).build()).build(),
      CacheType.builder().No(NoCache.builder().build()).build(),
      CacheType.builder().SingleThreaded(SingleThreadedCache.builder().entryCapacity(1).entryPruningTailSize(1).build()).build(),
      CacheType.builder().MultiThreaded(MultiThreadedCache.builder().entryCapacity(1).entryPruningTailSize(2).build()).build(),
      h.sharedBuiltIn(CacheType.builder().MultiThreaded(MultiThreadedCache.builder().entryCapacity(5).entryPruningTailSize(1).build()).build())
    );
    for (CacheType cache : unchecked) {
      inputs.add(h.input(branchKey).ttlSeconds(0).cache(cache).build());
    }
    // Storm tracking: the TTL must exceed the grace period, in seconds; milliseconds are rounded down.
    for (TimeUnits units : new TimeUnits[] { null, TimeUnits.Seconds, TimeUnits.Milliseconds }) {
      for (int grace : new int[] { 1, 5, 999, 1000, 5999 }) {
        for (long ttl : new long[] { 0, 1, 4, 5, 6, 998, 999, 1000 }) {
          inputs.add(h.input(branchKey).ttlSeconds(ttl).cache(storm(grace, units)).build());
        }
      }
    }
    // Partition ids are UTF-8.
    for (String partitionId : Arrays.asList("", "partition", "\u00fc\ud83d\ude00", "a\uD800b")) {
      inputs.add(h.input(branchKey).partitionId(partitionId).build());
    }
    // Exactly one of branch key id and supplier; a branch key id that is not UTF-8 fails only on encrypt.
    Supplier supplier = h.supplier(input -> id(branchKey));
    inputs.add(h.input(branchKey).branchKeyIdSupplier(supplier.nativeSupplier).build());
    inputs.add(h.input(null).build());
    inputs.add(h.input(null).branchKeyIdSupplier(supplier.nativeSupplier).build());
    inputs.add(h.input("a\uD800b").build());
    inputs.add(h.input("").build());
    // The logical key store name is UTF-8.
    KeyStore badName = h.storeNamed("a\uD800b");
    inputs.add(h.input(branchKey).keyStore(badName).build());
    // Check order: TTL against the cache, then the partition id, then the logical key store name, then the branch key id and supplier.
    inputs.add(h.input(null).ttlSeconds(5).partitionId("a\uD800b").build());
    inputs.add(h.input(null).partitionId("a\uD800b").build());
    inputs.add(h.input(null).partitionId("a\uD800b").keyStore(badName).build());
    inputs.add(h.input(null).keyStore(badName).build());
    for (CreateAwsKmsHierarchicalKeyringInput input : inputs) {
      if (input.ttlSeconds() == 0) {
        zeroTtlReference.add(h.knownDifferenceZeroTtl(input));
      } else {
        outcomes.record("Create", h.sameCreate(input));
      }
    }
    outcomes.assertBothSeen("Create");
    // The reference accepted a zero TTL at least once (with a cache it does not check), so the difference is real.
    assertTrue(zeroTtlReference.stream().anyMatch(outcome -> !outcome.startsWith("throws")), zeroTtlReference.toString());
    supplier.assertSameReceived();
  }

  // The public API takes times as Durations and has no time unit. Each old configuration in create(), given as the
  // equivalent Durations, builds a keyring exactly when the reference does, and otherwise fails with its message.
  @Test
  void durationSettingsMatchTheReferenceInEitherUnit() {
    for (TimeUnits units : new TimeUnits[] { TimeUnits.Seconds, TimeUnits.Milliseconds }) {
      LongFunction<Duration> unit = units == TimeUnits.Seconds ? Duration::ofSeconds : Duration::ofMillis;
      for (int grace : new int[] { 1, 5, 999, 1000, 5999 }) {
        software.amazon.cryptography.mpl.cache.StormTrackingCache settings = software.amazon.cryptography.mpl.cache.StormTrackingCache
          .builder()
          .entryCapacity(10)
          .entryPruningTailSize(1)
          .gracePeriod(unit.apply(grace))
          .graceInterval(unit.apply(1))
          .fanOut(5)
          .inFlightTtl(unit.apply(1))
          .sleep(Duration.ofMillis(5))
          .build();
        for (long ttl : new long[] { 1, 4, 5, 6, 998, 999, 1000 }) {
          CreateAwsKmsHierarchicalKeyringInput input = h.input(branchKey).ttlSeconds(ttl).cache(storm(grace, units)).build();
          String expected = ReferenceMpl.outcome(() -> ReferenceMpl.call(h.reference, "CreateAwsKmsHierarchicalKeyring", input) == null ? null : "keyring");
          String actual = ReferenceMpl.outcome(() ->
            AwsKmsHierarchicalKeyring
                .builder()
                .keyStore(input.keyStore().impl())
                .branchKeyId(branchKey)
                .ttl(Duration.ofSeconds(ttl))
                .cache(software.amazon.cryptography.mpl.cache.CacheType.stormTracking(settings))
                .build() == null
              ? null
              : "keyring"
          );
          assertEquals(message(expected), message(actual), units + " " + grace + ", ttl " + ttl);
        }
      }
    }
    // Millisecond configurations of whole seconds, which the native settings hold in seconds.
    // Inconsistent settings fail on both sides; the native message shows Durations, so only the outcome is compared.
    int[][] wholeSecondsInMillis = { { 5000, 1000, 1000 }, { 5000, 5000, 5000 }, { 5000, 6000, 1000 }, { 5000, 1000, 6000 }, { 5000, 2000, 1000 } };
    for (int[] times : wholeSecondsInMillis) {
      CacheType old = CacheType
        .builder()
        .StormTracking(
          StormTrackingCache
            .builder()
            .entryCapacity(10)
            .entryPruningTailSize(1)
            .gracePeriod(times[0])
            .graceInterval(times[1])
            .fanOut(5)
            .inFlightTTL(times[2])
            .sleepMilli(5)
            .timeUnits(TimeUnits.Milliseconds)
            .build()
        )
        .build();
      for (long ttl : new long[] { 4, 5, 6 }) {
        CreateAwsKmsHierarchicalKeyringInput input = h.input(branchKey).ttlSeconds(ttl).cache(old).build();
        String expected = ReferenceMpl.outcome(() -> ReferenceMpl.call(h.reference, "CreateAwsKmsHierarchicalKeyring", input) == null ? null : "keyring");
        String actual = ReferenceMpl.outcome(() ->
          AwsKmsHierarchicalKeyring
              .builder()
              .keyStore(input.keyStore().impl())
              .branchKeyId(branchKey)
              .ttl(Duration.ofSeconds(ttl))
              .cache(
                software.amazon.cryptography.mpl.cache.CacheType.stormTracking(
                  software.amazon.cryptography.mpl.cache.StormTrackingCache
                    .builder()
                    .entryCapacity(10)
                    .gracePeriod(Duration.ofMillis(times[0]))
                    .graceInterval(Duration.ofMillis(times[1]))
                    .fanOut(5)
                    .inFlightTtl(Duration.ofMillis(times[2]))
                    .sleep(Duration.ofMillis(5))
                    .build()
                )
              )
              .build() == null
            ? null
            : "keyring"
        );
        String where = Arrays.toString(times) + " ms, ttl " + ttl;
        assertEquals(expected.equals("keyring"), actual.equals("keyring"), where + ": " + expected + " / " + actual);
        if (message(expected).startsWith("When creating") && message(actual).startsWith("When creating")) {
          assertEquals(message(expected), message(actual), where);
        }
      }
    }
  }

  // "keyring", or the message of the exception; the two MPLs throw different exception classes.
  private static String message(String outcome) {
    return outcome.startsWith("throws ") ? outcome.substring(outcome.indexOf(": ") + 2) : outcome;
  }

  // Storm-tracking settings that pass the consistency check: graceInterval <= inFlightTTL <= gracePeriod.
  private static CacheType storm(int gracePeriod, TimeUnits units) {
    return CacheType
      .builder()
      .StormTracking(
        StormTrackingCache
          .builder()
          .entryCapacity(10)
          .entryPruningTailSize(1)
          .gracePeriod(gracePeriod)
          .graceInterval(1)
          .fanOut(5)
          .inFlightTTL(1)
          .sleepMilli(5)
          .timeUnits(units)
          .build()
      )
      .build();
  }

  @Test
  void stormSettingsFailBeforeTheTtlCheck() {
    // Native validates storm-tracking settings when they are built (register R20); Dafny checked the TTL first.
    CacheType inconsistent = CacheType
      .builder()
      .StormTracking(
        StormTrackingCache.builder().entryCapacity(1).entryPruningTailSize(1).gracePeriod(5).graceInterval(6).fanOut(1).inFlightTTL(5).sleepMilli(1).build()
      )
      .build();
    CreateAwsKmsHierarchicalKeyringInput lowTtl = h.input(branchKey).ttlSeconds(5).cache(inconsistent).build();
    String expected = ReferenceMpl.outcome(() -> ReferenceMpl.call(h.reference, "CreateAwsKmsHierarchicalKeyring", lowTtl));
    String actual = ReferenceMpl.outcome(() -> MPL.CreateAwsKmsHierarchicalKeyring(lowTtl));
    assertTrue(expected.contains("the ttlSeconds of the KeyRing must be greater than the gracePeriod"), expected);
    assertTrue(actual.contains("graceInterval"), actual);
    // With a valid TTL both report the settings.
    h.sameCreate(lowTtl.toBuilder().ttlSeconds(6).build());
  }

  //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
  //= type=test
  //# If a decryption succeeds, this keyring MUST add the resulting
  //# plaintext data key to the decryption materials and return the
  //# modified materials.
  //
  //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
  //= type=test
  //# OnEncrypt MUST append a new [encrypted data key](../structures.md#encrypted-data-key)
  //# to the encrypted data key list in the [encryption materials](../structures.md#encryption-materials)
  //
  //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
  //= type=test
  //# [key provider id](../structures.md#key-provider-id): MUST be UTF8 Encoded "aws-kms-hierarchy"
  //
  //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
  //= type=test
  //# [key provider info](../structures.md#key-provider-information): MUST be the UTF8 Encoded AWS DDB response `branch-key-id`
  //
  //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
  //= type=test
  //# [ciphertext](../structures.md#ciphertext): MUST be serialized as the [hierarchical keyring ciphertext](#ciphertext)
  @Test
  void eachSideDecryptsTheOther() {
    String version = h.active(branchKey).branchKeyVersion();
    Supplier supplier = h.supplier(input -> id(input.encryptionContext().containsKey("other") ? otherBranchKey : branchKey));
    List<Pair> keyrings = Arrays.asList(
      h.keyrings(h.input(branchKey).build()),
      h.keyrings(h.input(null).branchKeyIdSupplier(supplier.nativeSupplier).build())
    );
    for (Pair keyring : keyrings) {
      for (AlgorithmSuiteId suite : allSuites()) {
        for (Map<String, String> encryptionContext : Arrays.asList(map(), map("a", "b", "\u00fc", "\ud83d\ude00"))) {
          for (boolean withDataKey : new boolean[] { false, true }) {
            EncryptionMaterials start = encryptionMaterials(suite, encryptionContext, withDataKey);
            String context = ReferenceMpl.describe(suite) + " " + encryptionContext + " data key " + withDataKey;
            EncryptionMaterials nativeResult = keyring.nativeEncrypt(start);
            EncryptionMaterials referenceResult = keyring.referenceEncrypt(start);
            assertEquals(masked(referenceResult, withDataKey, 0), masked(nativeResult, withDataKey, 0), context);
            assertLayout(nativeResult, suite, branchKey, version);
            for (EncryptionMaterials result : Arrays.asList(nativeResult, referenceResult)) {
              String decrypted = keyring.assertSameDecrypt(outcomes, decryptionMaterials(result), result.encryptedDataKeys(), context);
              assertEquals(ReferenceMpl.describe(expectedDecryption(result)), decrypted, context);
            }
          }
        }
      }
    }
    supplier.assertSameReceived();
  }

  // The encrypted data key this keyring added: provider id, the branch key id as provider info, and
  // salt (16) || IV (12) || version (16) || wrapped key || tag (16), after the intermediate-wrapped data key for DBE suites.
  private static void assertLayout(EncryptionMaterials materials, AlgorithmSuiteId suite, String branchKeyId, String version) {
    EncryptedDataKey edk = materials.encryptedDataKeys().get(materials.encryptedDataKeys().size() - 1);
    assertEquals(PROVIDER_ID, edk.keyProviderId());
    assertArrayEquals(branchKeyId.getBytes(StandardCharsets.UTF_8), array(edk.keyProviderInfo()));
    int keyLength = Convert.suite(suite).dataKeyLength();
    int offset = Convert.suite(suite).usesIntermediateKeyWrapping() ? keyLength + 16 : 0;
    byte[] ciphertext = array(edk.ciphertext());
    assertEquals(offset + 16 + 12 + 16 + keyLength + 16, ciphertext.length);
    assertArrayEquals(uuidBytes(version), Arrays.copyOfRange(ciphertext, offset + 28, offset + 44));
  }

  @Test
  void aNewVersionWrapsNewKeysAndOldKeysStillDecrypt() {
    Pair keyring = h.keyrings(h.input(branchKey).cache(CacheType.builder().No(NoCache.builder().build()).build()).build());
    EncryptionMaterials before = keyring.nativeEncrypt(encryptionMaterials(esdk(), map("a", "b"), false));
    h.nativeStore.VersionKey(VersionKeyInput.builder().branchKeyIdentifier(branchKey).build());
    String version = h.active(branchKey).branchKeyVersion();
    EncryptionMaterials after = keyring.nativeEncrypt(encryptionMaterials(esdk(), map("a", "b"), false));
    assertLayout(after, esdk(), branchKey, version);
    assertTrue(!Arrays.equals(versionOf(before), versionOf(after)));
    for (EncryptionMaterials result : Arrays.asList(before, after, keyring.referenceEncrypt(encryptionMaterials(esdk(), map(), false)))) {
      assertEquals(ReferenceMpl.describe(expectedDecryption(result)), keyring.assertSameDecrypt(outcomes, decryptionMaterials(result), result.encryptedDataKeys(), ""));
    }
  }

  private static byte[] versionOf(EncryptionMaterials materials) {
    return Arrays.copyOfRange(array(materials.encryptedDataKeys().get(0).ciphertext()), 28, 44);
  }

  private static AlgorithmSuiteId esdk() {
    return allSuites().get(0);
  }

  @Test
  void encryptFailures() {
    Pair keyring = h.keyrings(h.input(branchKey).build());
    for (AlgorithmSuiteId suite : allSuites()) {
      EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false);
      EncryptionMaterials withKey = encryptionMaterials(suite, map("a", "b"), true);
      int dataKeyLength = array(withKey.plaintextDataKey()).length;
      List<EncryptionMaterials> pool = new ArrayList<>();
      pool.add(start.toBuilder().plaintextDataKey(ByteBuffer.wrap(bytes(dataKeyLength + 1, 3))).build());
      pool.add(start.toBuilder().encryptionContext(map()).build());
      pool.add(start.toBuilder().requiredEncryptionContextKeys(Collections.singletonList("missing")).build());
      pool.add(start.toBuilder().encryptedDataKeys(Collections.singletonList(edk("x", new byte[0], new byte[0]))).build());
      pool.add(withKey.toBuilder().encryptedDataKeys(Collections.singletonList(edk("x", new byte[0], new byte[0]))).build());
      pool.add(start.toBuilder().signingKey(start.signingKey() == null ? ByteBuffer.wrap(bytes(48, 1)) : null).build());
      pool.add(start.toBuilder().symmetricSigningKeys(Collections.singletonList(ByteBuffer.wrap(bytes(32, 1)))).build());
      // A context that cannot be serialized as AAD.
      pool.add(encryptionMaterials(suite, map(repeat('k', 65536), "v"), false));
      pool.add(start);
      for (EncryptionMaterials materials : pool) {
        keyring.assertSameEncrypt(outcomes, materials, ReferenceMpl.describe(suite), 0);
      }
    }
    // A branch key id that is not UTF-8, and one the key store does not have.
    for (String id : Arrays.asList("a\uD800b", "missing", "")) {
      h.keyrings(h.input(id).build()).assertSameEncrypt(outcomes, encryptionMaterials(esdk(), map(), false), id, 0);
    }
    outcomes.assertBothSeen("OnEncrypt");
  }

  @Test
  void suppliers() {
    List<Supplier> suppliers = Arrays.asList(
      h.supplier(input -> id("bad".equals(input.encryptionContext().get("tenant")) ? "a\uD800b" : input.encryptionContext().get("tenant"))),
      h.supplier(input -> null),
      h.supplier(input -> {
        throw new IllegalStateException("supplier failed");
      }),
      h.supplier(input -> {
        throw AwsCryptographicMaterialProvidersException.builder().message("modeled failure").build();
      })
    );
    EncryptionMaterials encrypted = h.keyrings(h.input(branchKey).build()).nativeEncrypt(encryptionMaterials(esdk(), map("tenant", branchKey), false));
    DecryptionMaterials decrypted = h
      .keyrings(h.input(branchKey).build())
      .nativeDecrypt(decryptionMaterials(encrypted, map("tenant", branchKey)), encrypted.encryptedDataKeys());
    for (Supplier supplier : suppliers) {
      Pair keyring = h.keyrings(h.input(null).branchKeyIdSupplier(supplier.nativeSupplier).build());
      for (Map<String, String> context : Arrays.asList(map("tenant", branchKey), map("tenant", otherBranchKey), map("tenant", "bad"))) {
        keyring.assertSameEncrypt(outcomes, encryptionMaterials(esdk(), context, false), context.toString(), 0);
        keyring.assertSameDecrypt(outcomes, decryptionMaterials(encrypted, context), encrypted.encryptedDataKeys(), context.toString());
      }
      // Materials that already hold a data key fail before the supplier is called.
      keyring.assertSameDecrypt(outcomes, decrypted, encrypted.encryptedDataKeys(), "data key given");
      supplier.assertSameReceived();
    }
    outcomes.assertBothSeen("OnEncrypt");
    outcomes.assertBothSeen("OnDecrypt");
  }

  @Test
  void decryptFailures() {
    Pair keyring = h.keyrings(h.input(branchKey).build());
    Pair otherKeyring = h.keyrings(h.input(otherBranchKey).build());
    for (AlgorithmSuiteId suite : allSuites()) {
      EncryptionMaterials encrypted = keyring.nativeEncrypt(encryptionMaterials(suite, map("a", "b"), false));
      EncryptedDataKey good = encrypted.encryptedDataKeys().get(0);
      byte[] info = array(good.keyProviderInfo());
      byte[] ciphertext = array(good.ciphertext());
      int keyLength = Convert.suite(suite).dataKeyLength();
      int offset = Convert.suite(suite).usesIntermediateKeyWrapping() ? keyLength + 16 : 0;
      DecryptionMaterials materials = decryptionMaterials(encrypted);
      byte[] otherInfo = otherBranchKey.getBytes(StandardCharsets.UTF_8);

      List<List<EncryptedDataKey>> edkLists = new ArrayList<>();
      edkLists.add(Collections.emptyList());
      edkLists.add(Collections.singletonList(good));
      edkLists.add(Collections.singletonList(edk("other", info, ciphertext)));
      edkLists.add(Collections.singletonList(edk("aws-kms-hierarchx", info, ciphertext)));
      // Another branch key: no match, and the message lists the version; a key too short to show one fails the message.
      edkLists.add(Arrays.asList(edk("other", "info".getBytes(StandardCharsets.UTF_8), ciphertext), edk(PROVIDER_ID, otherInfo, ciphertext)));
      edkLists.add(Collections.singletonList(edk(PROVIDER_ID, otherInfo, Arrays.copyOf(ciphertext, offset + 43))));
      edkLists.add(Collections.singletonList(edk(PROVIDER_ID, otherInfo, Arrays.copyOf(ciphertext, offset + 44))));
      if (offset > 0) {
        edkLists.add(Collections.singletonList(edk(PROVIDER_ID, otherInfo, Arrays.copyOf(ciphertext, offset - 1))));
      }
      // A provider info that is not UTF-8 fails the whole call, even after a match.
      edkLists.add(Collections.singletonList(edk(PROVIDER_ID, new byte[] { (byte) 0xff }, ciphertext)));
      edkLists.add(Arrays.asList(good, edk(PROVIDER_ID, new byte[] { (byte) 0xc3 }, ciphertext)));
      // Another provider's info is not decoded.
      edkLists.add(Arrays.asList(edk("other", new byte[] { (byte) 0xff }, ciphertext), good));
      // Lengths around each check: intermediate material, version, and the exact wrapped length.
      for (int length : new int[] { 0, offset - 1, offset, offset + 43, offset + 44, ciphertext.length - 1, ciphertext.length + 1 }) {
        if (length >= 0) {
          edkLists.add(Collections.singletonList(edk(PROVIDER_ID, info, Arrays.copyOf(ciphertext, length))));
        }
      }
      // Each part changed: the intermediate-wrapped data key, salt, IV, version (the key store has no such version),
      // wrapped key, and tag.
      for (int index : new int[] { 0, offset, offset + 16, offset + 28, offset + 43, offset + 44, ciphertext.length - 1 }) {
        edkLists.add(Collections.singletonList(edk(PROVIDER_ID, info, flip(ciphertext, index))));
      }
      // Failures before a success, and a success before a failure.
      edkLists.add(Arrays.asList(edk("other", info, ciphertext), edk(PROVIDER_ID, info, flip(ciphertext, ciphertext.length - 1)), good));
      edkLists.add(Arrays.asList(good, edk(PROVIDER_ID, info, flip(ciphertext, 0))));
      edkLists.add(Arrays.asList(edk(PROVIDER_ID, info, flip(ciphertext, offset + 30)), edk(PROVIDER_ID, info, new byte[3])));

      for (List<EncryptedDataKey> edks : edkLists) {
        keyring.assertSameDecrypt(outcomes, materials, edks, ReferenceMpl.describe(suite));
        otherKeyring.assertSameDecrypt(outcomes, materials, edks, ReferenceMpl.describe(suite));
      }
      // The encryption context is in the AAD.
      keyring.assertSameDecrypt(outcomes, decryptionMaterials(encrypted, map("a", "c")), Collections.singletonList(good), "");
      // Materials that are not valid, or already hold a data key.
      if (materials.verificationKey() != null) {
        keyring.assertSameDecrypt(outcomes, materials.toBuilder().verificationKey(null).build(), Collections.singletonList(good), "");
      }
      DecryptionMaterials missingRequired = materials.toBuilder().requiredEncryptionContextKeys(Collections.singletonList("missing")).build();
      keyring.assertSameDecrypt(outcomes, missingRequired, Collections.singletonList(good), "");
      keyring.assertSameDecrypt(outcomes, keyring.nativeDecrypt(materials, Collections.singletonList(good)), Collections.singletonList(good), "");
      // A context that cannot be serialized fails each key, not the call.
      DecryptionMaterials unserializable = decryptionMaterials(encrypted, map(repeat('k', 65536), "v"));
      keyring.assertSameDecrypt(outcomes, unserializable, Arrays.asList(good, good), "");
      keyring.assertSameDecrypt(outcomes, unserializable, Collections.emptyList(), "");
    }
    outcomes.assertBothSeen("OnDecrypt");
  }

  @Test
  void keyStoreFailures() {
    CacheType noCache = CacheType.builder().No(NoCache.builder().build()).build();
    Pair keyring = h.keyrings(h.input(branchKey).cache(noCache).build());
    EncryptionMaterials encrypted = keyring.nativeEncrypt(encryptionMaterials(esdk(), map(), false));
    DecryptionMaterials materials = decryptionMaterials(encrypted);
    h.aws.clearRequests();
    List<ServiceError> kmsErrors = Arrays.asList(
      ServiceError.accessDenied("not allowed"),
      ServiceError.throttling("slow down"),
      ServiceError.of("KMSInternalException", "internal"),
      ServiceError.of("DisabledException", "disabled")
    );
    for (ServiceError error : kmsErrors) {
      h.aws.nativeAws.kms().fail("Decrypt", h.kmsKey, error);
      sameEncrypt(keyring, encryptionMaterials(esdk(), map(), false));
      sameDecrypt(keyring, materials, encrypted.encryptedDataKeys());
      h.aws.nativeAws.kms().clearFailures();
      h.sameRequests();
    }
    h.aws.nativeAws.dynamoDb().fail("GetItem", ServiceError.of("com.amazonaws.dynamodb.v20120810#ProvisionedThroughputExceededException", "busy"));
    sameEncrypt(keyring, encryptionMaterials(esdk(), map(), false));
    sameDecrypt(keyring, materials, encrypted.encryptedDataKeys());
    h.aws.nativeAws.dynamoDb().clearFailures();
    h.sameRequests();
    // A store with another logical name cannot decrypt the branch key: the name is in its KMS encryption context.
    Pair otherStore = h.keyrings(h.input(branchKey).keyStore(h.storeNamed("other-logical-name")).cache(noCache).build());
    sameEncrypt(otherStore, encryptionMaterials(esdk(), map(), false));
    sameDecrypt(otherStore, materials, encrypted.encryptedDataKeys());
    h.sameRequests();
    // Success is recorded, so failures are not vacuous.
    sameDecrypt(keyring, materials, encrypted.encryptedDataKeys());
    outcomes.assertBothSeen("OnDecrypt");
  }

  // Outcomes with request ids masked: each side's AWS calls get their own.
  private String sameEncrypt(Pair keyring, EncryptionMaterials materials) {
    String expected = KeyStoreHarness.outcome(() -> masked(keyring.referenceEncrypt(materials), false, 0));
    String actual = KeyStoreHarness.outcome(() -> masked(keyring.nativeEncrypt(materials), false, 0));
    assertEquals(expected, actual);
    return outcomes.record("OnEncrypt", actual);
  }

  private String sameDecrypt(Pair keyring, DecryptionMaterials materials, List<EncryptedDataKey> edks) {
    String expected = KeyStoreHarness.outcome(() -> ReferenceMpl.call(keyring.referenceKeyring, "OnDecrypt", decryptInput(materials, edks)));
    String actual = KeyStoreHarness.outcome(() -> keyring.nativeKeyring.OnDecrypt(decryptInput(materials, edks)));
    assertEquals(expected, actual);
    return outcomes.record("OnDecrypt", actual);
  }
}
