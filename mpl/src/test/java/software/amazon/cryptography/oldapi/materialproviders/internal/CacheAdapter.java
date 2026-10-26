// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders.internal;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import software.amazon.cryptography.oldapi.keystore.model.BeaconKeyMaterials;
import software.amazon.cryptography.oldapi.keystore.model.BranchKeyMaterials;
import software.amazon.cryptography.oldapi.materialproviders.ICryptographicMaterialsCache;
import software.amazon.cryptography.oldapi.materialproviders.model.CacheType;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.MultiThreadedCache;
import software.amazon.cryptography.oldapi.materialproviders.model.SingleThreadedCache;
import software.amazon.cryptography.oldapi.materialproviders.model.StormTrackingCache;
import software.amazon.cryptography.oldapi.materialproviders.model.TimeUnits;
import software.amazon.cryptography.mpl.EncryptionContext;
import software.amazon.cryptography.mpl.SecretBytes;
import software.amazon.cryptography.mpl.cache.CryptographicMaterialsCache;
import software.amazon.cryptography.mpl.internal.KeyMaterialsAccess;
import software.amazon.cryptography.mpl.internal.cache.StormSettings;

/**
 * Test adapter: converts the old cache model to the native one,
 * and copies cache entries the way the Dafny-based MPL's Java conversion did.
 */
public final class CacheAdapter {

  /**
   * Stands for a cached encryption or decryption materials entry, which a native cache entry cannot hold.
   * The hierarchical keyring only tells branch keys from everything else, so any non-branch-key entry serves.
   */
  static final software.amazon.cryptography.mpl.keystore.BeaconKeyMaterials NOT_A_KEY = KeyMaterialsAccess.beaconKey(
    "",
    EncryptionContext.empty(),
    null,
    new HashMap<>()
  );

  private CacheAdapter() {}

  /** Seconds since the epoch as an instant; past {@link Instant#MAX} as {@code Instant.MAX}, the native keyring's expiry limit. */
  static Instant instant(long epochSecond) {
    return epochSecond > Instant.MAX.getEpochSecond() ? Instant.MAX : Instant.ofEpochSecond(epochSecond);
  }

  /**
   * The native cache type. A {@code Shared} cache is a customer object in the old API;
   * {@code sharedCache} turns it into a native one.
   */
  public static software.amazon.cryptography.mpl.cache.CacheType cacheType(
    CacheType old,
    Function<ICryptographicMaterialsCache, CryptographicMaterialsCache> sharedCache
  ) {
    if (old.Default() != null) {
      return software.amazon.cryptography.mpl.cache.CacheType.defaultCache(old.Default().entryCapacity());
    }
    if (old.No() != null) {
      return software.amazon.cryptography.mpl.cache.CacheType.noCache();
    }
    if (old.SingleThreaded() != null) {
      SingleThreadedCache c = old.SingleThreaded();
      return software.amazon.cryptography.mpl.cache.CacheType.singleThreaded(c.entryCapacity(), tailSize(c.entryPruningTailSize()));
    }
    if (old.MultiThreaded() != null) {
      MultiThreadedCache c = old.MultiThreaded();
      return software.amazon.cryptography.mpl.cache.CacheType.multiThreaded(c.entryCapacity(), tailSize(c.entryPruningTailSize()));
    }
    if (old.StormTracking() != null) {
      // Through the internal settings, which hold any old configuration, its time unit included.
      StormTrackingCache c = old.StormTracking();
      StormSettings settings = StormSettings.create(
        c.entryCapacity(),
        tailSize(c.entryPruningTailSize()),
        c.gracePeriod(),
        c.graceInterval(),
        c.fanOut(),
        c.inFlightTTL(),
        c.sleepMilli(),
        c.timeUnits() != TimeUnits.Milliseconds
      );
      return software.amazon.cryptography.mpl.cache.CacheType.stormTracking(settings.toPublic());
    }
    return software.amazon.cryptography.mpl.cache.CacheType.shared(sharedCache.apply(old.Shared()));
  }

  // An unset optional int reads as 0, which the Dafny-based MPL took as absent (OptionalCountingNumber).
  private static int tailSize(int entryPruningTailSize) {
    return entryPruningTailSize <= 0 ? 1 : entryPruningTailSize;
  }

  public static software.amazon.cryptography.mpl.keystore.BranchKeyMaterials toNative(BranchKeyMaterials old) {
    Boundary.utf8(old.branchKeyVersion());
    Boundary.encryptionContext(old.encryptionContext());
    return KeyMaterialsAccess.branchKey(
      old.branchKeyIdentifier(),
      old.branchKeyVersion(),
      EncryptionContext.copyOf(old.encryptionContext()),
      SecretBytes.copyOf(Buffers.toArray(old.branchKey()))
    );
  }

  public static BranchKeyMaterials toOld(software.amazon.cryptography.mpl.keystore.BranchKeyMaterials materials) {
    return BranchKeyMaterials
      .builder()
      .branchKeyIdentifier(materials.branchKeyIdentifier())
      .branchKeyVersion(materials.branchKeyVersion())
      .encryptionContext(new HashMap<>(materials.encryptionContext()))
      .branchKey(ByteBuffer.wrap(materials.branchKey().toByteArray()))
      .build();
  }

  public static software.amazon.cryptography.mpl.keystore.BeaconKeyMaterials toNative(BeaconKeyMaterials old) {
    Boundary.encryptionContext(old.encryptionContext());
    Map<String, SecretBytes> hmacKeys = new LinkedHashMap<>();
    if (old.hmacKeys() != null) {
      for (Map.Entry<String, ByteBuffer> entry : old.hmacKeys().entrySet()) {
        hmacKeys.put(entry.getKey(), SecretBytes.copyOf(Buffers.toArray(entry.getValue())));
      }
    }
    return KeyMaterialsAccess.beaconKey(
      old.beaconKeyIdentifier(),
      EncryptionContext.copyOf(old.encryptionContext()),
      old.beaconKey() == null ? null : SecretBytes.copyOf(Buffers.toArray(old.beaconKey())),
      hmacKeys
    );
  }

  /** An empty map of HMAC keys is absent, as the Dafny-based MPL returned it. */
  public static BeaconKeyMaterials toOld(software.amazon.cryptography.mpl.keystore.BeaconKeyMaterials materials) {
    Map<String, ByteBuffer> hmacKeys = null;
    if (!materials.hmacKeys().isEmpty()) {
      hmacKeys = new HashMap<>();
      for (Map.Entry<String, SecretBytes> entry : materials.hmacKeys().entrySet()) {
        hmacKeys.put(entry.getKey(), ByteBuffer.wrap(entry.getValue().toByteArray()));
      }
    }
    return BeaconKeyMaterials
      .builder()
      .beaconKeyIdentifier(materials.beaconKeyIdentifier())
      .encryptionContext(new HashMap<>(materials.encryptionContext()))
      .beaconKey(materials.beaconKey().map(k -> ByteBuffer.wrap(k.toByteArray())).orElse(null))
      .hmacKeys(hmacKeys)
      .build();
  }

  /**
   * A deep copy, as a round trip through the Dafny-based MPL's conversion produced:
   * fresh buffers holding bytes {@code [0, limit)}, copied collections, an empty symmetric signing key list absent.
   * The native cache has no encryption or decryption entries, so these stay in the old shape.
   */
  public static EncryptionMaterials copy(EncryptionMaterials m) {
    List<EncryptedDataKey> edks = new ArrayList<>();
    for (EncryptedDataKey edk : m.encryptedDataKeys()) {
      edks.add(
        EncryptedDataKey
          .builder()
          .keyProviderId(edk.keyProviderId())
          .keyProviderInfo(copy(edk.keyProviderInfo()))
          .ciphertext(copy(edk.ciphertext()))
          .build()
      );
    }
    List<ByteBuffer> symmetric = null;
    if (Boundary.optional(m.symmetricSigningKeys()) != null) {
      symmetric = new ArrayList<>();
      for (ByteBuffer key : m.symmetricSigningKeys()) {
        symmetric.add(copy(key));
      }
    }
    return m
      .toBuilder()
      .algorithmSuite(m.algorithmSuite().toBuilder().binaryId(copy(m.algorithmSuite().binaryId())).build())
      .encryptionContext(new HashMap<>(m.encryptionContext()))
      .encryptedDataKeys(edks)
      .requiredEncryptionContextKeys(new ArrayList<>(m.requiredEncryptionContextKeys()))
      .plaintextDataKey(copy(m.plaintextDataKey()))
      .signingKey(copy(m.signingKey()))
      .symmetricSigningKeys(symmetric)
      .build();
  }

  public static DecryptionMaterials copy(DecryptionMaterials m) {
    return m
      .toBuilder()
      .algorithmSuite(m.algorithmSuite().toBuilder().binaryId(copy(m.algorithmSuite().binaryId())).build())
      .encryptionContext(new HashMap<>(m.encryptionContext()))
      .requiredEncryptionContextKeys(new ArrayList<>(m.requiredEncryptionContextKeys()))
      .plaintextDataKey(copy(m.plaintextDataKey()))
      .verificationKey(copy(m.verificationKey()))
      .symmetricSigningKey(copy(m.symmetricSigningKey()))
      .build();
  }

  private static ByteBuffer copy(ByteBuffer buffer) {
    return buffer == null ? null : ByteBuffer.wrap(Buffers.toArray(buffer));
  }
}
