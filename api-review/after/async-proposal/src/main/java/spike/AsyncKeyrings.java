package spike;

import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnDecryptResponse;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;

/** Adapters from the sync Keyring to AsyncKeyring. There is deliberately no async-to-sync adapter here. */
public final class AsyncKeyrings {
  private AsyncKeyrings() {}

  /**
   * For a keyring that may block (it calls KMS with a sync client, or DynamoDB, or a remote service):
   * runs it on {@code executor}. The executor is required; there is no ForkJoinPool.commonPool() default.
   */
  public static AsyncKeyring fromBlocking(Keyring keyring, Executor executor) {
    Objects.requireNonNull(keyring, "keyring");
    Objects.requireNonNull(executor, "executor");
    return new AsyncKeyring() {
      @Override
      public CompletableFuture<OnEncryptResponse> onEncrypt(OnEncryptRequest request) {
        return CompletableFuture.supplyAsync(() -> keyring.onEncrypt(request), executor);
      }

      @Override
      public CompletableFuture<OnDecryptResponse> onDecrypt(OnDecryptRequest request) {
        return CompletableFuture.supplyAsync(() -> keyring.onDecrypt(request), executor);
      }
    };
  }

  /**
   * For a keyring that never blocks (raw AES/RSA/ECDH, or a custom keyring doing only local crypto):
   * runs it on the calling thread and returns a completed future.
   */
  public static AsyncKeyring fromNonBlocking(Keyring keyring) {
    Objects.requireNonNull(keyring, "keyring");
    return new AsyncKeyring() {
      @Override
      public CompletableFuture<OnEncryptResponse> onEncrypt(OnEncryptRequest request) {
        return Futures.guard(() -> CompletableFuture.completedFuture(keyring.onEncrypt(request)));
      }

      @Override
      public CompletableFuture<OnDecryptResponse> onDecrypt(OnDecryptRequest request) {
        return Futures.guard(() -> CompletableFuture.completedFuture(keyring.onDecrypt(request)));
      }
    };
  }
}
