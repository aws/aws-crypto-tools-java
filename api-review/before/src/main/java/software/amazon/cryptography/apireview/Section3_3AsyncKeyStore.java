// Section 3.3 of the API review doc: Async key store, hierarchical keyring, and cache waits
// Before: the Dafny-based MPL 1.11.1, with ESDK 3.0.2 and DB-ESDK 3.3.0.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import com.amazonaws.encryptionsdk.AwsCrypto;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.GetActiveBranchKeyInput;
import software.amazon.cryptography.materialproviders.IBranchKeyIdSupplier;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CacheType;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsHierarchicalKeyringInput;
import software.amazon.cryptography.materialproviders.model.GetBranchKeyIdInput;
import software.amazon.cryptography.materialproviders.model.GetBranchKeyIdOutput;

final class Section3_3AsyncKeyStore {
  private Section3_3AsyncKeyStore() {}

  // 3.3: An async key store with the same requests
  static CompletableFuture<String> keyStore(KeyStore keyStore, String branchKeyId, Executor pool) {
    // @card 33-keystore
    // The key store is sync: a pool thread waits for DynamoDB, then KMS.
    CompletableFuture<String> version = CompletableFuture
        .supplyAsync(() -> keyStore.GetActiveBranchKey(
            GetActiveBranchKeyInput.builder().branchKeyIdentifier(branchKeyId).build()), pool)
        .thenApply(output -> output.branchKeyMaterials().branchKeyVersion());
    // @end
    return version;
  }

  static final class TenantBranchKeyIdSupplier implements IBranchKeyIdSupplier {
    private final String branchKeyIdA;
    private final String branchKeyIdB;

    TenantBranchKeyIdSupplier(String branchKeyIdA, String branchKeyIdB) {
      this.branchKeyIdA = branchKeyIdA;
      this.branchKeyIdB = branchKeyIdB;
    }

    @Override
    public GetBranchKeyIdOutput GetBranchKeyId(GetBranchKeyIdInput input) {
      String tenant = input.encryptionContext().get("tenant");
      return GetBranchKeyIdOutput.builder().branchKeyId("TenantA".equals(tenant) ? branchKeyIdA : branchKeyIdB).build();
    }
  }

  // 3.3: An async hierarchical keyring
  static CompletableFuture<byte[]> hierarchical(MaterialProviders mpl, AwsCrypto crypto, KeyStore keyStore,
      String branchKeyIdA, String branchKeyIdB, byte[] plaintext, Map<String, String> encryptionContext,
      Executor pool) {
    // @card 33-hier
    IKeyring keyring = mpl.CreateAwsKmsHierarchicalKeyring(CreateAwsKmsHierarchicalKeyringInput.builder()
        .keyStore(keyStore)
        .branchKeyIdSupplier(new TenantBranchKeyIdSupplier(branchKeyIdA, branchKeyIdB))
        .ttlSeconds(600)
        .build());
    // On a cache miss, the pool thread waits for DynamoDB, then KMS.
    CompletableFuture<byte[]> ciphertext = CompletableFuture.supplyAsync(
        () -> crypto.encryptData(keyring, plaintext, encryptionContext).getResult(), pool);
    // @end
    return ciphertext;
  }

  // 3.3: Waiting callers are futures, with the same rules
  static List<CompletableFuture<byte[]>> waiters(AwsCrypto crypto, IKeyring keyring, List<byte[]> records) {
    // @card 33-waiters
    // 200 records on 16 threads, through a keyring with a storm-tracking cache: on a cold cache one thread
    // fetches the branch key, 15 wait inside the cache, and the other records queue behind them.
    ExecutorService pool = Executors.newFixedThreadPool(16);
    List<CompletableFuture<byte[]>> pending = new ArrayList<>();
    for (byte[] record : records) {
      pending.add(CompletableFuture.supplyAsync(() -> crypto.encryptData(keyring, record).getResult(), pool));
    }
    // @end
    return pending;
  }

  // 3.3: One cache for both flavors
  static CompletableFuture<byte[]> oneCache(MaterialProviders mpl, AwsCrypto crypto, KeyStore keyStore,
      String branchKeyId, CacheType stormTracking, byte[] plaintext, Map<String, String> encryptionContext,
      Executor pool) {
    // @card 33-onecache
    IKeyring keyring = mpl.CreateAwsKmsHierarchicalKeyring(CreateAwsKmsHierarchicalKeyringInput.builder()
        .keyStore(keyStore).branchKeyId(branchKeyId).ttlSeconds(600).cache(stormTracking).build());
    // The sync path and the async path share the keyring and its cache; async is a pool thread.
    byte[] now = crypto.encryptData(keyring, plaintext, encryptionContext).getResult();
    CompletableFuture<byte[]> later = CompletableFuture.supplyAsync(
        () -> crypto.encryptData(keyring, plaintext, encryptionContext).getResult(), pool);
    // @end
    now.hashCode();
    return later;
  }
}
