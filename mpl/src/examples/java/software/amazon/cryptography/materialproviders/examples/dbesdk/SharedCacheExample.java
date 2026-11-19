// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.dbesdk;

import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.materialproviders.cache.CryptographicMaterialsCache;
import software.amazon.cryptography.materialproviders.cache.MultiThreadedCache;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;

/**
 * Customer example (SharedCacheAcrossHierarchicalKeyringsExample): one branch key cache for several hierarchical keyrings,
 * for example one per table, and for the beacon key source of searchable encryption.
 * Keyrings with the same partition id and key store share entries, so the second keyring needs no KMS call;
 * the beacon key source's entries live in their own scope of the same cache.
 */
public final class SharedCacheExample {

  private SharedCacheExample() {}

  /**
   * Writes and reads an item through one keyring, reads it again through another, then computes a beacon,
   * all on one cache: three key store reads in total.
   *
   * @return the beacon of the item's {@code sensitive_data}
   */
  public static String shareOneCache(BranchKeyStore keyStore, String branchKeyId) {
    CryptographicMaterialsCache shared = MultiThreadedCache.builder().entryCapacity(100).build();
    AwsKmsHierarchicalKeyring writerKeyring = hierarchical(keyStore, branchKeyId, shared);
    AwsKmsHierarchicalKeyring readerKeyring = hierarchical(keyStore, branchKeyId, shared);

    // Encrypt and decrypt use different cache entries: the active branch key, and the version that encrypted the item.
    // The writer's decrypt caches that version, so the reader's decrypt finds it.
    Map<String, String> item = ExampleItems.item("sharedCacheItem");
    Map<String, String> encrypted = ExampleItems.roundTrip(ExampleItems.encryptor(writerKeyring), item);
    ExampleItems.requireEqual(item, ExampleItems.encryptor(readerKeyring).decryptItem(encrypted));

    BeaconKeySource beacons = BeaconKeySource
      .singleKeyStore(keyStore, branchKeyId)
      .beaconNames(Collections.singletonList(SearchableEncryptionExample.BEACON_NAME))
      .cacheTtlSeconds(600)
      .cache(shared)
      .partitionId("shared-cache-example")
      .build();
    return SearchableEncryptionExample.beacon(beacons, branchKeyId, item.get(ExampleItems.SENSITIVE));
  }

  private static AwsKmsHierarchicalKeyring hierarchical(BranchKeyStore keyStore, String branchKeyId, CryptographicMaterialsCache shared) {
    return AwsKmsHierarchicalKeyring
      .builder()
      .keyStore(keyStore)
      .branchKeyId(branchKeyId)
      .ttl(Duration.ofMinutes(10))
      .cache(shared)
      // Without the same partition id, keyrings sharing a cache do not share entries.
      .partitionId("shared-cache-example")
      .build();
  }
}
