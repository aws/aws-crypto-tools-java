// Section 1.3 of the API review doc: Hierarchical keyring and caches
// After: the native MPL 2.0.0, with the ESDK 4.0 sketch and the DB-ESDK stand-ins (proposals).
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.time.Duration;
import java.util.Map;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.cache.DefaultCache;
import software.amazon.cryptography.materialproviders.cache.MultiThreadedCache;
import software.amazon.cryptography.materialproviders.cache.StormTrackingCache;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;
import software.amazon.cryptography.materialproviders.keystore.DynamoDbKeyStore;

final class Section1_3HierarchicalKeyringAndCaches {
  private Section1_3HierarchicalKeyringAndCaches() {}

  // 1.3: The hierarchical keyring builds itself
  static byte[] hierarchical(EsdkClient esdk, DynamoDbKeyStore keyStore, String branchKeyId, byte[] plaintext,
      Map<String, String> encryptionContext) {
    // @card 12-hier
    AwsKmsHierarchicalKeyring keyring = AwsKmsHierarchicalKeyring.builder()
        .keyStore(keyStore)
        .branchKeyId(branchKeyId)
        .ttl(Duration.ofMinutes(10))
        .build();
    byte[] ciphertext = esdk.encrypt(b -> b
        .plaintext(plaintext).keyring(keyring).encryptionContext(encryptionContext)).ciphertext();
    // @end
    return ciphertext;
  }

  // 1.3: Caches are objects
  static Keyring caches(DynamoDbKeyStore keyStore, String branchKeyId) {
    // @card 12-caches
    MultiThreadedCache cache = MultiThreadedCache.builder().entryCapacity(100).entryPruningTailSize(1).build();
    AwsKmsHierarchicalKeyring keyring = AwsKmsHierarchicalKeyring.builder()
        .keyStore(keyStore)
        .branchKeyId(branchKeyId)
        .ttl(Duration.ofMinutes(10))
        .cache(cache)
        .build();
    // @end
    return keyring;
  }

  // 1.3: Share a cache by passing the same object
  static Keyring[] share(DynamoDbKeyStore keyStore1, DynamoDbKeyStore keyStore2, String branchKeyId) {
    // @card 12-share
    DefaultCache sharedCache = DefaultCache.builder().entryCapacity(100).build();
    AwsKmsHierarchicalKeyring keyring1 = AwsKmsHierarchicalKeyring.builder()
        .keyStore(keyStore1).branchKeyId(branchKeyId).ttl(Duration.ofMinutes(10))
        .cache(sharedCache).partitionId("tenants").build();
    AwsKmsHierarchicalKeyring keyring2 = AwsKmsHierarchicalKeyring.builder()
        .keyStore(keyStore2).branchKeyId(branchKeyId).ttl(Duration.ofMinutes(10))
        .cache(sharedCache).partitionId("tenants").build();
    // @end
    return new Keyring[] {keyring1, keyring2};
  }

  // 1.3: Storm-tracking times are Durations
  static Keyring storm(DynamoDbKeyStore keyStore, String branchKeyId) {
    // @card 12-storm
    StormTrackingCache cache = StormTrackingCache.builder()
        .entryCapacity(1000)
        .gracePeriod(Duration.ofSeconds(10)).graceInterval(Duration.ofSeconds(1)).fanOut(20)
        .inFlightTtl(Duration.ofSeconds(10)).sleep(Duration.ofMillis(20))
        .build();
    AwsKmsHierarchicalKeyring keyring = AwsKmsHierarchicalKeyring.builder()
        .keyStore(keyStore).branchKeyId(branchKeyId).ttl(Duration.ofMinutes(10)).cache(cache).build();
    // @end
    return keyring;
  }

  // 1.3: The TTL check covers any storm-tracking cache
  static String ttlCheck(DynamoDbKeyStore keyStore, String branchKeyId) {
    // @card 12-ttlcheck
    StormTrackingCache sharedCache = StormTrackingCache.builder()
        .entryCapacity(1000).gracePeriod(Duration.ofSeconds(10))
        .build();
    try {
      AwsKmsHierarchicalKeyring.builder()
          .keyStore(keyStore).branchKeyId(branchKeyId).ttl(Duration.ofSeconds(10))
          .cache(sharedCache)
          .build();
    } catch (ValidationException e) {
      return "the TTL must be above the cache's grace period";
    }
    // @end
    return "built";
  }
}
