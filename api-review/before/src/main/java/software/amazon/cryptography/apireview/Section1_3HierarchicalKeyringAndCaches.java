// Section 1.3 of the API review doc: Hierarchical keyring and caches
// Before: the Dafny-based MPL 1.11.1, with ESDK 3.0.2 and DB-ESDK 3.3.0.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import com.amazonaws.encryptionsdk.AwsCrypto;
import java.util.Map;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsCache;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CacheType;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsHierarchicalKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateCryptographicMaterialsCacheInput;
import software.amazon.cryptography.materialproviders.model.DefaultCache;
import software.amazon.cryptography.materialproviders.model.MultiThreadedCache;
import software.amazon.cryptography.materialproviders.model.StormTrackingCache;
import software.amazon.cryptography.materialproviders.model.TimeUnits;

final class Section1_3HierarchicalKeyringAndCaches {
  private Section1_3HierarchicalKeyringAndCaches() {}

  // 1.3: The hierarchical keyring builds itself
  static byte[] hierarchical(MaterialProviders mpl, AwsCrypto crypto, KeyStore keyStore, String branchKeyId,
      byte[] plaintext, Map<String, String> encryptionContext) {
    // @card 12-hier
    IKeyring keyring = mpl.CreateAwsKmsHierarchicalKeyring(CreateAwsKmsHierarchicalKeyringInput.builder()
        .keyStore(keyStore)
        .branchKeyId(branchKeyId)
        .ttlSeconds(600)
        .build());
    byte[] ciphertext = crypto.encryptData(keyring, plaintext, encryptionContext).getResult();
    // @end
    return ciphertext;
  }

  // 1.3: Caches are objects
  static IKeyring caches(MaterialProviders mpl, KeyStore keyStore, String branchKeyId) {
    // @card 12-caches
    CacheType cache = CacheType.builder()
        .MultiThreaded(MultiThreadedCache.builder().entryCapacity(100).entryPruningTailSize(1).build())
        .build();
    IKeyring keyring = mpl.CreateAwsKmsHierarchicalKeyring(CreateAwsKmsHierarchicalKeyringInput.builder()
        .keyStore(keyStore)
        .branchKeyId(branchKeyId)
        .ttlSeconds(600)
        .cache(cache)
        .build());
    // @end
    return keyring;
  }

  // 1.3: Share a cache by passing the same object
  static IKeyring[] share(MaterialProviders mpl, KeyStore keyStore1, KeyStore keyStore2, String branchKeyId) {
    // @card 12-share
    ICryptographicMaterialsCache sharedCache = mpl.CreateCryptographicMaterialsCache(
        CreateCryptographicMaterialsCacheInput.builder()
            .cache(CacheType.builder().Default(DefaultCache.builder().entryCapacity(100).build()).build())
            .build());
    CacheType shared = CacheType.builder().Shared(sharedCache).build();
    IKeyring keyring1 = mpl.CreateAwsKmsHierarchicalKeyring(CreateAwsKmsHierarchicalKeyringInput.builder()
        .keyStore(keyStore1).branchKeyId(branchKeyId).ttlSeconds(600).cache(shared).partitionId("tenants").build());
    IKeyring keyring2 = mpl.CreateAwsKmsHierarchicalKeyring(CreateAwsKmsHierarchicalKeyringInput.builder()
        .keyStore(keyStore2).branchKeyId(branchKeyId).ttlSeconds(600).cache(shared).partitionId("tenants").build());
    // @end
    return new IKeyring[] {keyring1, keyring2};
  }

  // 1.3: Storm-tracking times are Durations
  static IKeyring storm(MaterialProviders mpl, KeyStore keyStore, String branchKeyId) {
    // @card 12-storm
    CacheType cache = CacheType.builder()
        .StormTracking(StormTrackingCache.builder()
            .entryCapacity(1000)
            .gracePeriod(10).graceInterval(1).fanOut(20)
            .inFlightTTL(10).sleepMilli(20)
            .timeUnits(TimeUnits.Seconds)
            .build())
        .build();
    IKeyring keyring = mpl.CreateAwsKmsHierarchicalKeyring(CreateAwsKmsHierarchicalKeyringInput.builder()
        .keyStore(keyStore).branchKeyId(branchKeyId).ttlSeconds(600).cache(cache).build());
    // @end
    return keyring;
  }

  // 1.3: The TTL check covers any storm-tracking cache
  static IKeyring ttlCheck(MaterialProviders mpl, KeyStore keyStore, String branchKeyId) {
    // @card 12-ttlcheck
    ICryptographicMaterialsCache sharedCache = mpl.CreateCryptographicMaterialsCache(
        CreateCryptographicMaterialsCacheInput.builder()
            .cache(CacheType.builder().StormTracking(StormTrackingCache.builder()
                .entryCapacity(1000).gracePeriod(10).graceInterval(1).fanOut(20).inFlightTTL(10).sleepMilli(20)
                .build()).build())
            .build());
    // A TTL at or below the 10-second grace period builds: the Shared variant is not checked.
    IKeyring keyring = mpl.CreateAwsKmsHierarchicalKeyring(CreateAwsKmsHierarchicalKeyringInput.builder()
        .keyStore(keyStore).branchKeyId(branchKeyId).ttlSeconds(10)
        .cache(CacheType.builder().Shared(sharedCache).build())
        .build());
    // @end
    return keyring;
  }
}
