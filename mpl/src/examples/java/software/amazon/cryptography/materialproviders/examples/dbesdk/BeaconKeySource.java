// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.dbesdk;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.LongSupplier;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.cache.CacheEntry;
import software.amazon.cryptography.materialproviders.cache.CacheKey;
import software.amazon.cryptography.materialproviders.cache.CryptographicMaterialsCache;
import software.amazon.cryptography.materialproviders.cache.DefaultCache;
import software.amazon.cryptography.materialproviders.cache.GetCacheEntryRequest;
import software.amazon.cryptography.materialproviders.cache.PutCacheEntryRequest;
import software.amazon.cryptography.materialproviders.keystore.BeaconKeyMaterials;
import software.amazon.cryptography.materialproviders.keystore.KeyStore;

/**
 * Integration example: the DB-ESDK's beacon key source on the native MPL, per SearchInfo.dfy and ConfigToInfo.dfy
 * in the Dafny DB-ESDK.
 * It replaces "a beacon key retrieved elsewhere" in the native DB-ESDK's {@code BeaconKeyDerivation}.
 *
 * <p>A single key store always uses one beacon key; a multi key store reads the beacon key id from an item attribute
 * (or a query value). Both read beacon keys with {@link KeyStore#getBeaconKey}, derive one HMAC key per configured
 * beacon, and cache the derived keys without the beacon key ({@link BeaconKeyMaterials#toHmacKeysOnly}).
 * The cache identifier is a SHA-384 that includes a partition id and the key store's logical name,
 * so a cache shared with hierarchical keyrings or other beacon key sources keeps their entries apart.
 * A cached entry is used only while it is at most {@code cacheTtlSeconds} old by this source's TTL,
 * even if another source sharing the cache put it with a longer one.
 */
public final class BeaconKeySource {

  // CacheConstants.dfy: the hierarchical keyring's resource id, and the scope that separates searchable encryption.
  private static final byte RESOURCE_ID_HIERARCHICAL_KEYRING = 0x02;
  private static final byte SCOPE_ID_SEARCHABLE_ENCRYPTION = 0x03;
  private static final String BEACON_INFO_PREFIX = "AWS_DBE_SCAN_BEACON";
  private static final int HMAC_KEY_LENGTH = 64;

  private final KeyStore keyStore;
  private final List<String> beaconNames;
  private final String keyId;
  private final String keyFieldName;
  private final long cacheTtlSeconds;
  private final CryptographicMaterialsCache cache;
  private final byte[] partitionIdBytes;
  private final byte[] logicalKeyStoreNameBytes;
  private final LongSupplier epochSeconds;

  private BeaconKeySource(Builder builder, CryptographicMaterialsCache cache) {
    this.keyStore = builder.keyStore;
    this.beaconNames = new ArrayList<>(builder.beaconNames);
    this.keyId = builder.keyId;
    this.keyFieldName = builder.keyFieldName;
    this.cacheTtlSeconds = builder.cacheTtlSeconds;
    this.cache = cache;
    this.partitionIdBytes = builder.partitionId != null ? builder.partitionId.getBytes(StandardCharsets.UTF_8) : randomUuidBytes();
    this.logicalKeyStoreNameBytes = keyStore.getKeyStoreInfo().logicalKeyStoreName().getBytes(StandardCharsets.UTF_8);
    this.epochSeconds = builder.epochSeconds;
  }

  /** The DB-ESDK's {@code SingleKeyStore}: one beacon key for every item. */
  public static Builder singleKeyStore(KeyStore keyStore, String keyId) {
    return new Builder(keyStore, Objects.requireNonNull(keyId, "keyId"), null);
  }

  /** The DB-ESDK's {@code MultiKeyStore}: the beacon key id is in the item attribute {@code keyFieldName}. */
  public static Builder multiKeyStore(KeyStore keyStore, String keyFieldName) {
    return new Builder(keyStore, null, Objects.requireNonNull(keyFieldName, "keyFieldName"));
  }

  /** The beacon key id for an item (or for the attribute values of a query). */
  public String keyIdFor(Map<String, String> item) {
    if (keyId != null) {
      return keyId;
    }
    String id = item.get(keyFieldName);
    if (id == null) {
      throw new IllegalArgumentException("No beacon key id in attribute " + keyFieldName);
    }
    return id;
  }

  /**
   * One HMAC key per beacon name, derived from the beacon key {@code beaconKeyId}.
   * The caller owns the returned keys and should destroy them.
   */
  public Map<String, SecretBytes> hmacKeys(String beaconKeyId) {
    // Per getKeysCache: a cache hit within this source's TTL, else the key store, then put with expiry now + TTL.
    CacheKey key = CacheKey.of(cacheIdentifier(beaconKeyId));
    Optional<CacheEntry> entry = cache.getCacheEntry(GetCacheEntryRequest.builder().key(key).build()).entry();
    long now = epochSeconds.getAsLong();
    if (entry.isPresent() && now - entry.get().creationTime().getEpochSecond() <= cacheTtlSeconds) {
      BeaconKeyMaterials cached = entry
        .get()
        .beaconKeyMaterials()
        .filter(materials -> materials.beaconKeyIdentifier().equals(beaconKeyId))
        .orElseThrow(() -> new IllegalStateException("Invalid Material Type."));
      return copies(cached.hmacKeys());
    }
    BeaconKeyMaterials materials = keyStore.getBeaconKey(b -> b.branchKeyId(beaconKeyId)).beaconKeyMaterials();
    SecretBytes beaconKey = materials.beaconKey().orElseThrow(() -> new IllegalStateException("beacon key unexpectedly empty"));
    Map<String, SecretBytes> keys = new LinkedHashMap<>();
    try {
      for (String name : beaconNames) {
        keys.put(name, hmacKey(beaconKey, name));
      }
      cache.putCacheEntry(
        PutCacheEntryRequest.builder()
          .key(key)
          .entry(CacheEntry.builder().beaconKeyMaterials(materials.toHmacKeysOnly(keys)).creationTime(Instant.ofEpochSecond(now)).expiryTime(Instant.ofEpochSecond(now + cacheTtlSeconds)).build())
          .build()
      );
    } catch (RuntimeException e) {
      keys.values().forEach(SecretBytes::destroy);
      throw e;
    }
    return keys;
  }

  // HKDF-SHA-512 with no salt and info "AWS_DBE_SCAN_BEACON" + beacon name, as SearchInfo.dfy GetBeaconKey.
  static SecretBytes hmacKey(SecretBytes beaconKey, String beaconName) {
    byte[] info = (BEACON_INFO_PREFIX + beaconName).getBytes(StandardCharsets.UTF_8);
    byte[] ikm = beaconKey.toByteArray();
    byte[] key = null;
    try {
      key = Hkdf.derive("HmacSHA512", new byte[0], ikm, info, HMAC_KEY_LENGTH);
      return SecretBytes.copyOf(key);
    } finally {
      Arrays.fill(ikm, (byte) 0);
      if (key != null) {
        Arrays.fill(key, (byte) 0);
      }
    }
  }

  // The cache owns its entry's keys.
  private static Map<String, SecretBytes> copies(Map<String, SecretBytes> keys) {
    Map<String, SecretBytes> copies = new LinkedHashMap<>();
    for (Map.Entry<String, SecretBytes> entry : keys.entrySet()) {
      copies.put(entry.getKey(), entry.getValue().copy());
    }
    return copies;
  }

  // As SearchInfo.dfy GenerateUuidBytes: the 16 bytes of a random UUID.
  private static byte[] randomUuidBytes() {
    UUID uuid = UUID.randomUUID();
    return ByteBuffer.allocate(16).putLong(uuid.getMostSignificantBits()).putLong(uuid.getLeastSignificantBits()).array();
  }

  // SHA-384 of: resource id, scope id, partition id, logical key store name, beacon key id; separated by 0x00.
  private byte[] cacheIdentifier(String beaconKeyId) {
    ByteArrayOutputStream identifier = new ByteArrayOutputStream();
    identifier.write(RESOURCE_ID_HIERARCHICAL_KEYRING);
    identifier.write(0);
    identifier.write(SCOPE_ID_SEARCHABLE_ENCRYPTION);
    identifier.write(0);
    identifier.write(partitionIdBytes, 0, partitionIdBytes.length);
    identifier.write(0);
    identifier.write(logicalKeyStoreNameBytes, 0, logicalKeyStoreNameBytes.length);
    identifier.write(0);
    byte[] id = beaconKeyId.getBytes(StandardCharsets.UTF_8);
    identifier.write(id, 0, id.length);
    try {
      return MessageDigest.getInstance("SHA-384").digest(identifier.toByteArray());
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Not thread-safe. Requires {@code cacheTtlSeconds} from 1 to 2^32 - 1, the Dafny uint32 range.
   * Default cache, per ConfigToInfo.dfy: a new {@link DefaultCache} of 1 entry for a single key store, 1000 entries for a multi key store.
   */
  public static final class Builder {

    private final KeyStore keyStore;
    private final String keyId;
    private final String keyFieldName;
    private List<String> beaconNames = new ArrayList<>();
    private long cacheTtlSeconds;
    private CryptographicMaterialsCache cache;
    private String partitionId;
    private LongSupplier epochSeconds = () -> System.currentTimeMillis() / 1000;

    private Builder(KeyStore keyStore, String keyId, String keyFieldName) {
      this.keyStore = Objects.requireNonNull(keyStore, "keyStore");
      this.keyId = keyId;
      this.keyFieldName = keyFieldName;
    }

    /** The table's standard beacons, each of which gets an HMAC key. */
    public Builder beaconNames(Collection<String> beaconNames) {
      this.beaconNames = new ArrayList<>(beaconNames);
      return this;
    }

    public Builder cacheTtlSeconds(long cacheTtlSeconds) {
      this.cacheTtlSeconds = cacheTtlSeconds;
      return this;
    }

    /** The cache, which may also be given to hierarchical keyrings. */
    public Builder cache(CryptographicMaterialsCache cache) {
      this.cache = cache;
      return this;
    }

    /** Sources and keyrings sharing a cache share entries only with an equal partition id; default: a random id. */
    public Builder partitionId(String partitionId) {
      this.partitionId = partitionId;
      return this;
    }

    /** The clock, in epoch seconds; for tests of the TTL. */
    public Builder clock(LongSupplier epochSeconds) {
      this.epochSeconds = Objects.requireNonNull(epochSeconds, "epochSeconds");
      return this;
    }

    public BeaconKeySource build() {
      if (cacheTtlSeconds < 1) {
        throw new IllegalArgumentException("Beacon Cache TTL must be at least 1.");
      }
      if (cacheTtlSeconds > 0xFFFFFFFFL) {
        throw new IllegalArgumentException("Beacon Cache TTL must fit in 32 bits.");
      }
      CryptographicMaterialsCache built = cache != null ? cache : DefaultCache.builder().entryCapacity(keyId != null ? 1 : 1000).build();
      return new BeaconKeySource(this, built);
    }
  }
}
