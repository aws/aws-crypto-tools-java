// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static software.amazon.cryptography.materialproviders.KeyStoreHarness.WEST;
import static software.amazon.cryptography.materialproviders.KeyStoreHarness.config;
import static software.amazon.cryptography.materialproviders.KeyStoreHarness.keyArn;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Pattern;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.BranchKeyMaterials;
import software.amazon.cryptography.keystore.model.CreateKeyInput;
import software.amazon.cryptography.keystore.model.GetActiveBranchKeyInput;
import software.amazon.cryptography.keystore.model.KeyStoreConfig;
import software.amazon.cryptography.materialproviders.KeyringTests.Pair;
import software.amazon.cryptography.materialproviders.model.CacheType;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsHierarchicalKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateCryptographicMaterialsCacheInput;
import software.amazon.cryptography.materialproviders.model.DeleteCacheEntryInput;
import software.amazon.cryptography.materialproviders.model.EntryDoesNotExist;
import software.amazon.cryptography.materialproviders.model.GetBranchKeyIdInput;
import software.amazon.cryptography.materialproviders.model.GetBranchKeyIdOutput;
import software.amazon.cryptography.materialproviders.model.GetCacheEntryInput;
import software.amazon.cryptography.materialproviders.model.GetCacheEntryOutput;
import software.amazon.cryptography.materialproviders.model.PutCacheEntryInput;
import software.amazon.cryptography.materialproviders.model.UpdateUsageMetadataInput;

/**
 * The hierarchical keyring on both sides over one key store table:
 * both sides' key stores read the same fake endpoint, so both see the same branch keys,
 * and each side's requests are recorded under its own label.
 */
final class HierarchicalHarness implements AutoCloseable {

  static final String PROVIDER_ID = "aws-kms-hierarchy";
  private static final Pattern TIMES = Pattern.compile("(creationTime|expiryTime)=\\d+");

  final KeyStoreHarness aws = KeyStoreHarness.shared();
  final String kmsKey = aws.symmetricKey(WEST);
  final KeyStore nativeStore;
  final Object referenceStore;
  final Object reference = ReferenceMpl.materialProviders();

  HierarchicalHarness() {
    aws.createTable(WEST);
    KeyStoreHarness.Stores stores = KeyStoreHarness.stores(config(keyArn(kmsKey), aws.kms(WEST), aws.ddb(WEST)).build());
    nativeStore = stores.nativeStore;
    referenceStore = stores.referenceStore;
    ReferenceMpl.registerTwin(nativeStore, referenceStore);
  }

  /** Both sides' key stores for another logical key store name over the same table and KMS key. */
  KeyStore storeNamed(String logicalKeyStoreName) {
    KeyStoreConfig config = config(keyArn(kmsKey), aws.kms(WEST), aws.ddb(WEST)).logicalKeyStoreName(logicalKeyStoreName).build();
    KeyStoreHarness.Stores stores = KeyStoreHarness.stores(config);
    ReferenceMpl.registerTwin(stores.nativeStore, stores.referenceStore);
    return stores.nativeStore;
  }

  /** A new branch key, created through the native store; returns its id. */
  String createBranchKey() {
    return nativeStore.CreateKey(CreateKeyInput.builder().build()).branchKeyIdentifier();
  }

  BranchKeyMaterials active(String branchKeyId) {
    return nativeStore.GetActiveBranchKey(GetActiveBranchKeyInput.builder().branchKeyIdentifier(branchKeyId).build()).branchKeyMaterials();
  }

  CreateAwsKmsHierarchicalKeyringInput.Builder input(String branchKeyId) {
    return CreateAwsKmsHierarchicalKeyringInput.builder().keyStore(nativeStore).branchKeyId(branchKeyId).ttlSeconds(600);
  }

  /** The keyring built on both sides; both builds must succeed. */
  Pair keyrings(CreateAwsKmsHierarchicalKeyringInput input) {
    return new Pair(KeyringTests.MPL.CreateAwsKmsHierarchicalKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsHierarchicalKeyring", input));
  }

  /** The outcome of building the keyring on each side: "keyring" or the exception; asserts they are equal. */
  String sameCreate(CreateAwsKmsHierarchicalKeyringInput input) {
    String expected = ReferenceMpl.outcome(() -> created(ReferenceMpl.call(reference, "CreateAwsKmsHierarchicalKeyring", input)));
    String actual = ReferenceMpl.outcome(() -> created(KeyringTests.MPL.CreateAwsKmsHierarchicalKeyring(input)));
    assertEquals(expected, actual, () -> describe(input));
    return actual;
  }

  /**
   * A TTL of zero: the specification requires a TTL greater than zero, which the native keyring enforces,
   * while the Dafny-based MPL accepts zero with an explicit cache. Returns the reference outcome.
   */
  String knownDifferenceZeroTtl(CreateAwsKmsHierarchicalKeyringInput input) {
    String expected = ReferenceMpl.outcome(() -> created(ReferenceMpl.call(reference, "CreateAwsKmsHierarchicalKeyring", input)));
    String actual = ReferenceMpl.outcome(() -> created(KeyringTests.MPL.CreateAwsKmsHierarchicalKeyring(input)));
    assertEquals(
      "throws software.amazon.cryptography.materialproviders.model.AwsCryptographicMaterialProvidersException: `ttl` must be greater than 0",
      actual,
      () -> describe(input)
    );
    return expected;
  }

  // The key store and a shared cache are left out: they are clients, not model values.
  private static String describe(CreateAwsKmsHierarchicalKeyringInput input) {
    CacheType cache = input.cache();
    return (
      "branchKeyId " + input.branchKeyId() + ", supplier " + (input.branchKeyIdSupplier() != null) + ", ttlSeconds " + input.ttlSeconds() +
      ", partitionId " + input.partitionId() + ", cache " + (cache == null || cache.Shared() != null ? cache : ReferenceMpl.describe(cache))
    );
  }

  private static String created(Object keyring) {
    return keyring == null ? "null" : "keyring";
  }

  /** A cache from CreateCryptographicMaterialsCache on each side, as a Shared cache type. */
  CacheType sharedBuiltIn(CacheType type) {
    CreateCryptographicMaterialsCacheInput input = CreateCryptographicMaterialsCacheInput.builder().cache(type).build();
    ICryptographicMaterialsCache nativeCache = KeyringTests.MPL.CreateCryptographicMaterialsCache(input);
    ReferenceMpl.registerTwin(nativeCache, ReferenceMpl.call(reference, "CreateCryptographicMaterialsCache", input));
    return CacheType.builder().Shared(nativeCache).build();
  }

  /** Both sides' requests since the last clear, with random values masked; asserts they are equal and returns them. */
  List<String> sameRequests() {
    List<String> requests = aws.requests(ReferenceAws.NATIVE);
    assertEquals(aws.requests(ReferenceAws.REFERENCE), requests, "requests");
    aws.clearRequests();
    return requests;
  }

  /** A caller's supplier, on both sides, running {@code behavior} on what it receives. */
  Supplier supplier(Function<GetBranchKeyIdInput, GetBranchKeyIdOutput> behavior) {
    return new Supplier(behavior);
  }

  static final class Supplier {

    final List<String> nativeReceived = new ArrayList<>();
    final List<String> referenceReceived = new ArrayList<>();
    final IBranchKeyIdSupplier nativeSupplier;

    Supplier(Function<GetBranchKeyIdInput, GetBranchKeyIdOutput> behavior) {
      nativeSupplier = BranchKeyIdSupplier.wrap(
        (IBranchKeyIdSupplier) input -> {
          nativeReceived.add("GetBranchKeyId " + ReferenceMpl.describe(input));
          return behavior.apply(input);
        }
      );
      Object reference = ReferenceMpl.customer(
        "materialproviders.IBranchKeyIdSupplier",
        referenceReceived,
        input -> behavior.apply((GetBranchKeyIdInput) input)
      );
      ReferenceMpl.registerTwin(nativeSupplier, reference);
    }

    /** Asserts both sides' suppliers received the same calls since the last check. */
    void assertSameReceived() {
      assertEquals(referenceReceived, nativeReceived, "supplier calls");
      nativeReceived.clear();
      referenceReceived.clear();
    }
  }

  static GetBranchKeyIdOutput id(String branchKeyId) {
    return GetBranchKeyIdOutput.builder().branchKeyId(branchKeyId).build();
  }

  /** How a caller's cache answers; the default methods are a plain map, missing entries throw EntryDoesNotExist. */
  interface CacheScript {
    default GetCacheEntryOutput get(GetCacheEntryInput input, Map<String, GetCacheEntryOutput> stored) {
      GetCacheEntryOutput output = stored.get(ReferenceMpl.describe(input.identifier()));
      if (output == null) {
        throw EntryDoesNotExist.builder().message("Entry does not exist").build();
      }
      return output;
    }

    default void put(PutCacheEntryInput input, Map<String, GetCacheEntryOutput> stored) {
      stored.put(
        ReferenceMpl.describe(input.identifier()),
        GetCacheEntryOutput
          .builder()
          .materials(input.materials())
          .creationTime(input.creationTime())
          .expiryTime(input.expiryTime())
          .messagesUsed(0)
          .bytesUsed(0)
          .build()
      );
    }
  }

  /** A caller's cache on both sides: each side's has its own entries, and both record the calls they receive. */
  static final class CustomerCache {

    final List<String> nativeReceived = new ArrayList<>();
    final List<String> referenceReceived = new ArrayList<>();
    final ICryptographicMaterialsCache nativeCache;

    CustomerCache(CacheScript script) {
      // The old model's CacheType wraps a Shared cache; the twin must be the wrapper.
      nativeCache = CryptographicMaterialsCache.wrap(new Scripted(script, nativeReceived));
      Scripted referenceBehavior = new Scripted(script, new ArrayList<>());
      Object reference = ReferenceMpl.customer("materialproviders.ICryptographicMaterialsCache", referenceReceived, referenceBehavior::dispatch);
      ReferenceMpl.registerTwin(nativeCache, reference);
    }

    CacheType cacheType() {
      return CacheType.builder().Shared(nativeCache).build();
    }

    /** Asserts both caches received the same calls since the last check, entry times masked; returns them. */
    List<String> assertSameReceived() {
      List<String> received = masked(nativeReceived);
      assertEquals(masked(referenceReceived), received, "cache calls");
      nativeReceived.clear();
      referenceReceived.clear();
      return received;
    }

    private static List<String> masked(List<String> calls) {
      List<String> masked = new ArrayList<>();
      for (String call : calls) {
        masked.add(TIMES.matcher(call).replaceAll("$1=<time>"));
      }
      return masked;
    }
  }

  private static final class Scripted implements ICryptographicMaterialsCache {

    private final CacheScript script;
    private final List<String> received;
    private final Map<String, GetCacheEntryOutput> stored = new HashMap<>();

    Scripted(CacheScript script, List<String> received) {
      this.script = script;
      this.received = received;
    }

    Object dispatch(Object input) {
      if (input instanceof GetCacheEntryInput) {
        return script.get((GetCacheEntryInput) input, stored);
      }
      if (input instanceof PutCacheEntryInput) {
        script.put((PutCacheEntryInput) input, stored);
        return null;
      }
      throw new UnsupportedOperationException(input.getClass().getName());
    }

    @Override
    public GetCacheEntryOutput GetCacheEntry(GetCacheEntryInput input) {
      received.add("GetCacheEntry " + ReferenceMpl.describe(input));
      return (GetCacheEntryOutput) dispatch(input);
    }

    @Override
    public void PutCacheEntry(PutCacheEntryInput input) {
      received.add("PutCacheEntry " + ReferenceMpl.describe(input));
      dispatch(input);
    }

    @Override
    public void DeleteCacheEntry(DeleteCacheEntryInput input) {
      throw new UnsupportedOperationException("DeleteCacheEntry");
    }

    @Override
    public void UpdateUsageMetadata(UpdateUsageMetadataInput input) {
      throw new UnsupportedOperationException("UpdateUsageMetadata");
    }
  }

  /**
   * The cache identifier the keyring uses, computed from the spec: SHA-384 of
   * {@code 0x02 0x00 scope 0x00 partition 0x00 logical name 0x00 branch key id [0x00 version]},
   * scope 0x01 on encrypt and 0x02 on decrypt.
   */
  static ByteBuffer cacheId(String partitionId, String logicalName, String branchKeyId, String version) {
    StringBuilder text = new StringBuilder();
    text.append(partitionId).append('\0').append(logicalName).append('\0').append(branchKeyId);
    if (version != null) {
      text.append('\0').append(version);
    }
    byte[] suffix = text.toString().getBytes(StandardCharsets.UTF_8);
    byte[] identifier = ByteBuffer.allocate(4 + suffix.length).put((byte) 2).put((byte) 0).put((byte) (version == null ? 1 : 2)).put((byte) 0).put(suffix).array();
    try {
      return ByteBuffer.wrap(MessageDigest.getInstance("SHA-384").digest(identifier));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  static byte[] uuidBytes(String uuid) {
    UUID parsed = UUID.fromString(uuid);
    return ByteBuffer.allocate(16).putLong(parsed.getMostSignificantBits()).putLong(parsed.getLeastSignificantBits()).array();
  }

  @Override
  public void close() {
    aws.close();
  }
}
