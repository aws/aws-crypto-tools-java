// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders.internal;

import software.amazon.cryptography.materialproviders.cache.CacheKey;
import software.amazon.cryptography.materialproviders.exceptions.ThrottlingException;
import software.amazon.cryptography.materialproviders.internal.cache.CacheEngine;
import software.amazon.cryptography.materialproviders.internal.cache.Lookup;
import software.amazon.cryptography.oldapi.materialproviders.ICryptographicMaterialsCache;
import software.amazon.cryptography.oldapi.materialproviders.model.DeleteCacheEntryInput;
import software.amazon.cryptography.oldapi.materialproviders.model.EntryDoesNotExist;
import software.amazon.cryptography.oldapi.materialproviders.model.GetCacheEntryInput;
import software.amazon.cryptography.oldapi.materialproviders.model.GetCacheEntryOutput;
import software.amazon.cryptography.oldapi.materialproviders.model.InFlightTTLExceeded;
import software.amazon.cryptography.oldapi.materialproviders.model.Materials;
import software.amazon.cryptography.oldapi.materialproviders.model.OpaqueError;
import software.amazon.cryptography.oldapi.materialproviders.model.PutCacheEntryInput;
import software.amazon.cryptography.oldapi.materialproviders.model.UpdateUsageMetadataInput;

/**
 * Test adapter: the old cache interface over a native built-in cache.
 *
 * <p>The old interface also caches encryption and decryption materials and keeps usage counters,
 * which the native public cache dropped (register R4); the entries here carry both.
 */
public final class NativeCache implements ICryptographicMaterialsCache {

  // LocalCMC.dfy's limit (bug B6: not the int maximum). The counters exist only in this adapter (R4),
  // so it keeps the Dafny value: an entry whose counters would pass it is removed.
  private static final int INT32_MAX_VALUE = 0x7999_9999;

  private final CacheEngine<Entry> engine;

  public NativeCache(CacheEngine<Entry> engine) {
    this.engine = engine;
  }

  @Override
  public void PutCacheEntry(PutCacheEntryInput input) {
    CacheKey key = key(input.identifier());
    engine.put(key, new Entry(input), input.expiryTime());
  }

  @Override
  public GetCacheEntryOutput GetCacheEntry(GetCacheEntryInput input) {
    Lookup<Entry> lookup = lookup(key(input.identifier()));
    if (!lookup.isHit()) {
      throw EntryDoesNotExist.builder().message(lookup.missReason()).build();
    }
    Entry entry = lookup.value();
    synchronized (entry) {
      return GetCacheEntryOutput
        .builder()
        .materials(entry.materials())
        .creationTime(entry.creationTime)
        .expiryTime(entry.expiryTime)
        .messagesUsed(entry.messagesUsed)
        .bytesUsed(entry.bytesUsed)
        .build();
    }
  }

  @Override
  public void DeleteCacheEntry(DeleteCacheEntryInput input) {
    engine.remove(key(input.identifier()));
  }

  @Override
  public void UpdateUsageMetadata(UpdateUsageMetadataInput input) {
    int bytesUsed = input.bytesUsed();
    engine.retainIf(
      key(input.identifier()),
      entry -> {
        synchronized (entry) {
          if (entry.messagesUsed <= INT32_MAX_VALUE - 1 && entry.bytesUsed <= INT32_MAX_VALUE - bytesUsed) {
            entry.messagesUsed += 1;
            entry.bytesUsed += bytesUsed;
            return true;
          }
          return false;
        }
      }
    );
  }

  private Lookup<Entry> lookup(CacheKey key) {
    try {
      return engine.get(key);
    } catch (ThrottlingException e) {
      if (e.getCause() instanceof InterruptedException) {
        throw OpaqueError.builder().obj(e.getCause()).build();
      }
      throw InFlightTTLExceeded.builder().message(e.getMessage()).build();
    }
  }

  private static CacheKey key(java.nio.ByteBuffer identifier) {
    return CacheKey.of(Buffers.toArray(identifier));
  }

  /** A cached old-shape entry; the counters change under the entry's lock. */
  public static final class Entry {

    private final software.amazon.cryptography.keystore.BranchKeyMaterials branchKey;
    private final software.amazon.cryptography.keystore.BeaconKeyMaterials beaconKey;
    private final Materials encryptionOrDecryption;
    final long creationTime;
    final long expiryTime;
    int messagesUsed;
    int bytesUsed;

    Entry(PutCacheEntryInput input) {
      Materials m = input.materials();
      if (m.Encryption() != null) {
        Boundary.encryptionMaterials(m.Encryption());
        this.encryptionOrDecryption = Materials.builder().Encryption(CacheAdapter.copy(m.Encryption())).build();
      } else if (m.Decryption() != null) {
        Boundary.decryptionMaterials(m.Decryption());
        this.encryptionOrDecryption = Materials.builder().Decryption(CacheAdapter.copy(m.Decryption())).build();
      } else {
        this.encryptionOrDecryption = null;
      }
      this.branchKey = m.BranchKey() == null ? null : CacheAdapter.toNative(m.BranchKey());
      this.beaconKey = m.BeaconKey() == null ? null : CacheAdapter.toNative(m.BeaconKey());
      this.creationTime = input.creationTime();
      this.expiryTime = input.expiryTime();
      this.messagesUsed = input.messagesUsed();
      this.bytesUsed = input.bytesUsed();
    }

    Materials materials() {
      if (branchKey != null) {
        return Materials.builder().BranchKey(CacheAdapter.toOld(branchKey)).build();
      }
      if (beaconKey != null) {
        return Materials.builder().BeaconKey(CacheAdapter.toOld(beaconKey)).build();
      }
      if (encryptionOrDecryption.Encryption() != null) {
        return Materials.builder().Encryption(CacheAdapter.copy(encryptionOrDecryption.Encryption())).build();
      }
      return Materials.builder().Decryption(CacheAdapter.copy(encryptionOrDecryption.Decryption())).build();
    }
  }
}
