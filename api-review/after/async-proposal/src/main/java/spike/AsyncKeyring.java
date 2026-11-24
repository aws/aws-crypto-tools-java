package spike;

import java.util.concurrent.CompletableFuture;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnDecryptResponse;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;

/**
 * The async counterpart of {@code software.amazon.cryptography.materialproviders.Keyring}.
 *
 * <p>Same request and response types as the sync interface; only the return type differs, as
 * {@code KmsClient} and {@code KmsAsyncClient} share {@code DecryptRequest}/{@code DecryptResponse}.
 *
 * <p>Contract (what the SDK v2 async clients also promise):
 * <ul>
 *   <li>Never blocks the calling thread on I/O or on another caller. Returns quickly.
 *   <li>Reports every failure through the returned future, never by throwing. (The adapters enforce this.)
 *   <li>The future may complete on any thread, including an SDK response thread; callers that do
 *       heavy work in a dependent stage should use the {@code ...Async(fn, executor)} variants.
 * </ul>
 */
public interface AsyncKeyring {
  CompletableFuture<OnEncryptResponse> onEncrypt(OnEncryptRequest request);

  CompletableFuture<OnDecryptResponse> onDecrypt(OnDecryptRequest request);
}
