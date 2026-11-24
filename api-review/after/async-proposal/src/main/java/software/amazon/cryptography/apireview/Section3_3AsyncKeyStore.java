// Section 3.3 of the API review doc: Async key store, hierarchical keyring, and cache waits
// After (proposal): the async API, on the async spike and the proposal stubs.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import proposal.AsyncBranchKeyIdSupplier;
import proposal.AsyncDynamoDbKeyStore;
import proposal.AwsKmsHierarchicalAsyncKeyring;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;
import software.amazon.cryptography.materialproviders.cache.StormTrackingCache;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;
import software.amazon.cryptography.materialproviders.keyrings.BranchKeyIdSupplier;
import software.amazon.cryptography.materialproviders.keyrings.GetBranchKeyIdRequest;
import software.amazon.cryptography.materialproviders.keyrings.GetBranchKeyIdResponse;
import software.amazon.cryptography.materialproviders.keystore.DynamoDbKeyStore;
import software.amazon.cryptography.materialproviders.keystore.KmsConfiguration;

final class Section3_3AsyncKeyStore {
  private Section3_3AsyncKeyStore() {}

  // 3.3: An async key store with the same requests
  static CompletableFuture<String> keyStore(String tableName, String logicalKeyStoreName, String kmsKeyArn,
      DynamoDbAsyncClient ddbAsyncClient, KmsAsyncClient kmsAsyncClient, String branchKeyId) {
    // @card 33-keystore
    AsyncDynamoDbKeyStore asyncKeyStore = AsyncDynamoDbKeyStore.builder()
        .ddbTableName(tableName).logicalKeyStoreName(logicalKeyStoreName)
        .kmsConfiguration(KmsConfiguration.kmsKeyArn(kmsKeyArn))
        .ddbClient(ddbAsyncClient).kmsClient(kmsAsyncClient)
        .build();
    CompletableFuture<String> version = asyncKeyStore
        .getActiveBranchKey(b -> b.branchKeyId(branchKeyId))
        .thenApply(response -> response.branchKeyMaterials().branchKeyVersion());
    // @end
    return version;
  }

  static final class TenantBranchKeyIdSupplier implements BranchKeyIdSupplier {
    private final String branchKeyIdA;
    private final String branchKeyIdB;

    TenantBranchKeyIdSupplier(String branchKeyIdA, String branchKeyIdB) {
      this.branchKeyIdA = branchKeyIdA;
      this.branchKeyIdB = branchKeyIdB;
    }

    @Override
    public GetBranchKeyIdResponse getBranchKeyId(GetBranchKeyIdRequest request) {
      String tenant = request.encryptionContext().get("tenant");
      return GetBranchKeyIdResponse.builder().branchKeyId("TenantA".equals(tenant) ? branchKeyIdA : branchKeyIdB).build();
    }
  }

  // 3.3: An async hierarchical keyring
  static CompletableFuture<OnEncryptResponse> hierarchical(AsyncDynamoDbKeyStore asyncKeyStore, String branchKeyIdA,
      String branchKeyIdB, OnEncryptRequest request) {
    // @card 33-hier
    AwsKmsHierarchicalAsyncKeyring keyring = AwsKmsHierarchicalAsyncKeyring.builder()
        .keyStore(asyncKeyStore)
        .branchKeyIdSupplier(
            AsyncBranchKeyIdSupplier.fromNonBlocking(new TenantBranchKeyIdSupplier(branchKeyIdA, branchKeyIdB)))
        .ttl(Duration.ofMinutes(10))
        .build();
    // On a cache miss, the key store chains DynamoDB, then KMS, as futures.
    CompletableFuture<OnEncryptResponse> encrypted = keyring.onEncrypt(request);
    // @end
    return encrypted;
  }

  // 3.3: Waiting callers are futures, with the same rules
  static List<CompletableFuture<OnEncryptResponse>> waiters(AwsKmsHierarchicalAsyncKeyring keyring,
      List<OnEncryptRequest> requests) {
    // @card 33-waiters
    // 200 requests through a keyring with a storm-tracking cache, and no pool: on a cold cache one call
    // fetches the branch key, and the other callers wait as parked futures, not threads.
    List<CompletableFuture<OnEncryptResponse>> pending = new ArrayList<>();
    for (OnEncryptRequest request : requests) {
      pending.add(keyring.onEncrypt(request));
    }
    // @end
    return pending;
  }

  // 3.3: One cache for both flavors
  static Object[] oneCache(DynamoDbKeyStore keyStore, AsyncDynamoDbKeyStore asyncKeyStore, String branchKeyId) {
    // @card 33-onecache
    StormTrackingCache sharedCache = StormTrackingCache.builder().entryCapacity(1000).build();
    // A sync and an async keyring share one built-in cache.
    AwsKmsHierarchicalKeyring syncKeyring = AwsKmsHierarchicalKeyring.builder()
        .keyStore(keyStore).branchKeyId(branchKeyId).ttl(Duration.ofMinutes(10)).cache(sharedCache).build();
    AwsKmsHierarchicalAsyncKeyring asyncKeyring = AwsKmsHierarchicalAsyncKeyring.builder()
        .keyStore(asyncKeyStore).branchKeyId(branchKeyId).ttl(Duration.ofMinutes(10)).cache(sharedCache).build();
    // @end
    return new Object[] {syncKeyring, asyncKeyring};
  }
}
