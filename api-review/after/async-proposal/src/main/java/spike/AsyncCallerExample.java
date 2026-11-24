package spike;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;

/** How a caller uses the async KMS keyring and the adapters. No thread waits for KMS. */
public final class AsyncCallerExample {
  private AsyncCallerExample() {}

  public static CompletableFuture<Boolean> kmsRoundTrip(KmsAsyncClient kmsClient, String keyArn) {
    // 1. The same builder members as AwsKmsKeyring; only the client type differs.
    AsyncKeyring keyring = AwsKmsAsyncKeyring.builder().kmsKeyId(keyArn).kmsClient(kmsClient).build();
    AlgorithmSuite suite = EsdkAlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
    // 2. The same request types as the sync keyring; the call returns at once with a future.
    CompletableFuture<EncryptionMaterials> encrypted = keyring
        .onEncrypt(OnEncryptRequest.builder().materials(EncryptionMaterials.builder(suite).build()).build())
        .thenApply(r -> r.materials());
    // 3. Decrypt when encrypt completes; a failure arrives through the future as a MaterialProvidersException.
    return encrypted.thenCompose(m -> keyring
        .onDecrypt(OnDecryptRequest.builder()
            .materials(DecryptionMaterials.builder(suite).build())
            .encryptedDataKeys(m.encryptedDataKeys())
            .build())
        .thenApply(r -> r.materials().plaintextDataKey().get().contentEquals(m.plaintextDataKey().get())));
  }

  public static AsyncKeyring[] adapt(Keyring localKeyring, Keyring blockingKeyring, Executor blockingPool) {
    // A keyring that only computes runs inline; one that blocks runs on the caller's executor.
    AsyncKeyring inline = AsyncKeyrings.fromNonBlocking(localKeyring);
    AsyncKeyring offloaded = AsyncKeyrings.fromBlocking(blockingKeyring, blockingPool);
    return new AsyncKeyring[] {inline, offloaded};
  }
}
