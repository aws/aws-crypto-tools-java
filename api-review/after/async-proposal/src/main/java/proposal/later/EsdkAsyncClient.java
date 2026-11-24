package proposal.later;

import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.Consumer;
import org.reactivestreams.Publisher;
import software.amazon.cryptography.esdk.EncryptRequest;
import software.amazon.cryptography.esdk.EncryptResponse;
import software.amazon.cryptography.esdk.EncryptStreamRequest;

/**
 * Proposal, later than the EsdkAsyncClient stub: the client builder's executor, and streaming with Reactive Streams.
 * The one-shot calls are those of the EsdkAsyncClient stub.
 */
public interface EsdkAsyncClient {
  static Builder builder() {
    return new Builder();
  }

  CompletableFuture<EncryptResponse> encrypt(EncryptRequest request);

  default CompletableFuture<EncryptResponse> encrypt(Consumer<EncryptRequest.Builder> request) {
    EncryptRequest.Builder builder = EncryptRequest.builder();
    request.accept(builder);
    return encrypt(builder.build());
  }

  Publisher<ByteBuffer> encrypt(EncryptStreamRequest request, Publisher<ByteBuffer> plaintext);

  final class Builder {
    private Builder() {}

    public Builder executor(Executor executor) {
      return this;
    }

    public EsdkAsyncClient build() {
      throw new UnsupportedOperationException("proposal stub");
    }
  }
}
