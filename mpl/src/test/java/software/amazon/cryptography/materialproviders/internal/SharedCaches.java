// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Optional;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsCache;
import software.amazon.cryptography.materialproviders.model.DeleteCacheEntryInput;
import software.amazon.cryptography.materialproviders.model.EntryAlreadyExists;
import software.amazon.cryptography.materialproviders.model.EntryDoesNotExist;
import software.amazon.cryptography.materialproviders.model.GetCacheEntryInput;
import software.amazon.cryptography.materialproviders.model.GetCacheEntryOutput;
import software.amazon.cryptography.materialproviders.model.Materials;
import software.amazon.cryptography.materialproviders.model.PutCacheEntryInput;
import software.amazon.cryptography.mpl.cache.CacheEntry;
import software.amazon.cryptography.mpl.cache.CacheKey;

/**
 * Test adapter: an old-API cache given to a hierarchical keyring as {@code Shared}, as a native cache.
 *
 * <p>Every cache, including one from {@code CreateCryptographicMaterialsCache}, is called through the old interface,
 * and calls cross the boundary as in the Dafny-based MPL's wrapper:
 * a miss ({@code EntryDoesNotExist}) is empty, any other exception or unconvertible result fails as
 * {@link Boundary#crossing} describes.
 */
public final class SharedCaches {

  private SharedCaches() {}

  public static software.amazon.cryptography.mpl.cache.CryptographicMaterialsCache toNative(ICryptographicMaterialsCache cache) {
    return new Customer(cache);
  }

  private static final class Customer implements software.amazon.cryptography.mpl.cache.CryptographicMaterialsCache {

    private final ICryptographicMaterialsCache cache;

    Customer(ICryptographicMaterialsCache cache) {
      this.cache = cache;
    }

    @Override
    public Optional<CacheEntry> get(CacheKey key) {
      try {
        GetCacheEntryOutput output = cache.GetCacheEntry(GetCacheEntryInput.builder().identifier(identifier(key)).build());
        return Optional.of(toNative(output));
      } catch (EntryDoesNotExist e) {
        return Optional.empty();
      } catch (RuntimeException e) {
        throw Boundary.crossing(e);
      }
    }

    // The keyring puts only branch keys.
    @Override
    public void put(CacheKey key, CacheEntry entry) {
      try {
        cache.PutCacheEntry(
          PutCacheEntryInput
            .builder()
            .identifier(identifier(key))
            .materials(Materials.builder().BranchKey(CacheAdapter.toOld(entry.branchKeyMaterials().get())).build())
            .creationTime(entry.creationTime().getEpochSecond())
            .expiryTime(entry.expiryTime().getEpochSecond())
            .build()
        );
      } catch (EntryAlreadyExists e) {
        // The Dafny-based keyring ignored this failure of a put; the native cache interface has no such failure.
      } catch (RuntimeException e) {
        throw Boundary.crossing(e);
      }
    }

    @Override
    public void remove(CacheKey key) {
      try {
        cache.DeleteCacheEntry(DeleteCacheEntryInput.builder().identifier(identifier(key)).build());
      } catch (RuntimeException e) {
        throw Boundary.crossing(e);
      }
    }

    // The Dafny-based wrapper converted the result inside its try, so a result it could not convert failed like a thrown exception.
    private static CacheEntry toNative(GetCacheEntryOutput output) {
      Materials materials = output.materials();
      Instant creation = CacheAdapter.instant(output.creationTime());
      Instant expiry = CacheAdapter.instant(output.expiryTime());
      if (materials.BranchKey() != null) {
        return CacheEntry.of(CacheAdapter.toNative(materials.BranchKey()), creation, expiry);
      }
      if (materials.BeaconKey() != null) {
        return CacheEntry.of(CacheAdapter.toNative(materials.BeaconKey()), creation, expiry);
      }
      if (materials.Encryption() != null) {
        Boundary.encryptionMaterials(materials.Encryption());
      } else {
        Boundary.decryptionMaterials(materials.Decryption());
      }
      return CacheEntry.of(CacheAdapter.NOT_A_KEY, creation, expiry);
    }

    private static ByteBuffer identifier(CacheKey key) {
      return ByteBuffer.wrap(key.identifier());
    }
  }
}
