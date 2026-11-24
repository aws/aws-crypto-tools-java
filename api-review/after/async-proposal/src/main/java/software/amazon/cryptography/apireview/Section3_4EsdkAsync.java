// Section 3.4 of the API review doc: ESDK async
// After (proposal): the async API, on the async spike and the proposal stubs.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import software.amazon.cryptography.esdk.DecryptResponse;
import software.amazon.cryptography.esdk.EncryptRequest;
import software.amazon.cryptography.esdk.EncryptResponse;
import software.amazon.cryptography.esdk.EsdkAsyncClient;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.esdk.EsdkValidationException;
import spike.AsyncKeyring;

final class Section3_4EsdkAsync {
  private Section3_4EsdkAsync() {}

  // 3.4: EsdkAsyncClient takes the same requests
  static CompletableFuture<byte[]> esdkAsync(AsyncKeyring asyncKeyring, byte[] plaintext,
      Map<String, String> encryptionContext) {
    // @card 34-client
    EsdkAsyncClient esdkAsync = EsdkAsyncClient.create();
    CompletableFuture<byte[]> ciphertext = esdkAsync
        .encrypt(b -> b.plaintext(plaintext).keyring(asyncKeyring).encryptionContext(encryptionContext))
        .thenApply(EncryptResponse::ciphertext);
    CompletableFuture<byte[]> decrypted = ciphertext
        .thenCompose(c -> esdkAsync.decrypt(b -> b.ciphertext(c).keyring(asyncKeyring)))
        .thenApply(DecryptResponse::plaintext);
    // @end
    return decrypted;
  }

  // 3.4: Async materials go only to the async client
  static CompletableFuture<EncryptResponse> materials(EsdkClient esdk, EsdkAsyncClient esdkAsync,
      AsyncKeyring asyncKeyring, byte[] plaintext) {
    // @card 34-materials
    EncryptRequest request = EncryptRequest.builder().plaintext(plaintext).keyring(asyncKeyring).build();
    CompletableFuture<EncryptResponse> encrypted = esdkAsync.encrypt(request);
    try {
      esdk.encrypt(request);
    } catch (EsdkValidationException e) {
      // EsdkClient takes only sync materials; the message points to the adapters.
    }
    // @end
    return encrypted;
  }
}
