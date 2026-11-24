// Section 3.2 of the API review doc: Async keyrings, CMM, and supplier
// After (proposal): the async API, on the async spike and the proposal stubs.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import proposal.AsyncBranchKeyIdSupplier;
import proposal.AsyncCryptographicMaterialsManager;
import proposal.DefaultAsyncCryptographicMaterialsManager;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsRequest;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsResponse;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;
import software.amazon.cryptography.materialproviders.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.materialproviders.keyrings.GetBranchKeyIdResponse;
import spike.AsyncKeyring;
import spike.AsyncKeyrings;
import spike.AwsKmsAsyncKeyring;

final class Section3_2AsyncKeyrings {
  private Section3_2AsyncKeyrings() {}

  // 3.2: Async interfaces, in the same packages
  static void interfaces(AsyncKeyring asyncKeyring, GetEncryptionMaterialsRequest request, String tenantBranchKeyId) {
    // @card 32-ifaces
    AsyncCryptographicMaterialsManager cmm = DefaultAsyncCryptographicMaterialsManager.create(asyncKeyring);
    CompletableFuture<GetEncryptionMaterialsResponse> materials = cmm.getEncryptionMaterials(request);
    // One method, so a lambda works.
    AsyncBranchKeyIdSupplier supplier = supplierRequest -> CompletableFuture.completedFuture(
        GetBranchKeyIdResponse.builder().branchKeyId(tenantBranchKeyId).build());
    // @end
    materials.join();
    supplier.hashCode();
  }

  // 3.2: AwsKmsAsyncKeyring takes KmsAsyncClient
  static CompletableFuture<OnEncryptResponse> kmsKeyring(String keyArn, KmsAsyncClient appKms,
      OnEncryptRequest request) {
    // @card 32-kms
    // The keyring takes the application's KmsAsyncClient: no second client, and no pool.
    AsyncKeyring keyring = AwsKmsAsyncKeyring.builder().kmsKeyId(keyArn).kmsClient(appKms).build();
    CompletableFuture<OnEncryptResponse> encrypted = keyring.onEncrypt(request);
    // @end
    return encrypted;
  }

  // 3.2: Failures arrive through the future
  static CompletableFuture<String> failures(AsyncKeyring keyring, OnDecryptRequest request) {
    // @card 32-failures
    CompletableFuture<String> outcome = keyring
        .onDecrypt(request)
        .handle((response, e) -> {
          if (e == null) {
            return "decrypted";
          }
          Throwable cause = e instanceof CompletionException ? e.getCause() : e;
          return cause instanceof NoMatchingDataKeyException ? "no encrypted data key decrypted" : "failed: " + cause;
        });
    // @end
    return outcome;
  }

  // 3.2: Explicit adapters lift sync keyrings and CMMs
  static void adapters(Keyring blockingKeyring, Keyring rawAesKeyring, OnEncryptRequest request, Executor pool) {
    // @card 32-adapters
    // The proposal names these AsyncKeyring.fromBlocking and fromNonBlocking; the spike has them on AsyncKeyrings.
    AsyncKeyring offloaded = AsyncKeyrings.fromBlocking(blockingKeyring, pool);
    AsyncKeyring inline = AsyncKeyrings.fromNonBlocking(rawAesKeyring);
    CompletableFuture<OnEncryptResponse> fromBlocking = offloaded.onEncrypt(request);
    CompletableFuture<OnEncryptResponse> fromAes = inline.onEncrypt(request);
    // @end
    fromBlocking.join();
    fromAes.join();
  }
}
