// Section 3.2 of the API review doc: Async keyrings, CMM, and supplier
// Before: the Dafny-based MPL 1.11.1, with ESDK 3.0.2 and DB-ESDK 3.3.0.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.IBranchKeyIdSupplier;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CollectionOfErrors;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsKeyringInput;
import software.amazon.cryptography.materialproviders.model.GetBranchKeyIdInput;
import software.amazon.cryptography.materialproviders.model.GetBranchKeyIdOutput;
import software.amazon.cryptography.materialproviders.model.GetEncryptionMaterialsInput;
import software.amazon.cryptography.materialproviders.model.GetEncryptionMaterialsOutput;
import software.amazon.cryptography.materialproviders.model.OnDecryptInput;
import software.amazon.cryptography.materialproviders.model.OnEncryptInput;
import software.amazon.cryptography.materialproviders.model.OnEncryptOutput;

final class Section3_2AsyncKeyrings {
  private Section3_2AsyncKeyrings() {}

  // 3.2: Async interfaces, in the same packages
  static void interfaces(ICryptographicMaterialsManager cmm, GetEncryptionMaterialsInput input,
      IBranchKeyIdSupplier supplier, GetBranchKeyIdInput supplierInput, Executor pool) {
    // @card 32-ifaces
    // The CMM and the supplier are sync, so the application runs them on its pool.
    CompletableFuture<GetEncryptionMaterialsOutput> materials =
        CompletableFuture.supplyAsync(() -> cmm.GetEncryptionMaterials(input), pool);
    CompletableFuture<GetBranchKeyIdOutput> branchKeyId =
        CompletableFuture.supplyAsync(() -> supplier.GetBranchKeyId(supplierInput), pool);
    // @end
    materials.join();
    branchKeyId.join();
  }

  // 3.2: AwsKmsAsyncKeyring takes KmsAsyncClient
  static CompletableFuture<OnEncryptOutput> kmsKeyring(MaterialProviders mpl, String keyArn, KmsAsyncClient appKms,
      OnEncryptInput input) {
    // @card 32-kms
    // The application calls KMS with appKms, a KmsAsyncClient, but the keyring takes only a sync client.
    KmsClient esdkKms = KmsClient.create();
    IKeyring keyring = mpl.CreateAwsKmsKeyring(
        CreateAwsKmsKeyringInput.builder().kmsKeyId(keyArn).kmsClient(esdkKms).build());
    ExecutorService pool = Executors.newFixedThreadPool(16);
    CompletableFuture<OnEncryptOutput> encrypted = CompletableFuture.supplyAsync(() -> keyring.OnEncrypt(input), pool);
    // @end
    appKms.hashCode();
    return encrypted;
  }

  // 3.2: Failures arrive through the future
  static CompletableFuture<String> failures(IKeyring keyring, OnDecryptInput input, Executor pool) {
    // @card 32-failures
    CompletableFuture<String> outcome = CompletableFuture
        .supplyAsync(() -> keyring.OnDecrypt(input), pool)
        .handle((output, e) -> {
          if (e == null) {
            return "decrypted";
          }
          Throwable cause = e instanceof CompletionException ? e.getCause() : e;
          return cause instanceof CollectionOfErrors ? "no encrypted data key decrypted" : "failed: " + cause;
        });
    // @end
    return outcome;
  }

  // 3.2: Explicit adapters lift sync keyrings and CMMs
  static void adapters(IKeyring blockingKeyring, IKeyring rawAesKeyring, OnEncryptInput input, Executor pool) {
    // @card 32-adapters
    // The application decides for each keyring: its own keyring, which blocks, goes on the pool,
    // and the raw AES keyring, which only computes, runs on the caller's thread.
    CompletableFuture<OnEncryptOutput> fromBlocking =
        CompletableFuture.supplyAsync(() -> blockingKeyring.OnEncrypt(input), pool);
    CompletableFuture<OnEncryptOutput> fromAes =
        CompletableFuture.completedFuture(rawAesKeyring.OnEncrypt(input));
    // @end
    fromBlocking.join();
    fromAes.join();
  }
}
