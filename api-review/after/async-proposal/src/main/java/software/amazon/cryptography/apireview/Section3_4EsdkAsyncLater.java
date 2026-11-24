// Section 3.4 of the API review doc: ESDK async
// After (proposal): the async API, on the async spike and the proposal stubs.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.nio.ByteBuffer;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import org.reactivestreams.Publisher;
import proposal.later.EsdkAsyncClient;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.cryptography.esdk.EncryptResponse;
import software.amazon.cryptography.esdk.EncryptStreamRequest;
import spike.AsyncKeyring;

final class Section3_4EsdkAsyncLater {
  private Section3_4EsdkAsyncLater() {}

  // 3.4: Where the CPU work runs
  static CompletableFuture<byte[]> cpu(AsyncKeyring asyncKeyring, byte[] plaintext,
      Map<String, String> encryptionContext, Executor cpuPool) {
    // @card 34-cpu
    // By default the frames are encrypted on the thread that completed the KMS call; executor moves that work.
    EsdkAsyncClient esdkAsync = EsdkAsyncClient.builder().executor(cpuPool).build();
    CompletableFuture<byte[]> ciphertext = esdkAsync
        .encrypt(b -> b.plaintext(plaintext).keyring(asyncKeyring).encryptionContext(encryptionContext))
        .thenApply(EncryptResponse::ciphertext);
    // @end
    return ciphertext;
  }

  // 3.4: Streaming later, with Reactive Streams
  static AsyncRequestBody streaming(EsdkAsyncClient esdkAsync, EncryptStreamRequest request, Publisher<ByteBuffer> plaintext) {
    // @card 34-streaming
    // A later release: the plaintext and the ciphertext are Reactive Streams publishers, and the ciphertext
    // feeds an SDK request body.
    Publisher<ByteBuffer> ciphertext = esdkAsync.encrypt(request, plaintext);
    AsyncRequestBody body = AsyncRequestBody.fromPublisher(ciphertext);
    // @end
    return body;
  }
}
