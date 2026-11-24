package spike;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.awssdk.services.kms.model.InvalidCiphertextException;

/**
 * No network. Completes each call after a delay on its own thread, as the SDK completes futures on its
 * future-completion executor ("sdk-async-response-*") and never on the caller's thread.
 */
final class StubKmsAsyncClient implements KmsAsyncClient {
  final AtomicInteger calls = new AtomicInteger();
  private final ExecutorService completer = Executors.newFixedThreadPool(2, r -> {
    Thread t = new Thread(r, "stub-sdk-async-response");
    t.setDaemon(true);
    return t;
  });
  private final Map<ByteBuffer, byte[]> store = new ConcurrentHashMap<>();
  private final SecureRandom random = new SecureRandom();
  private final long delayMillis;

  StubKmsAsyncClient(long delayMillis) {
    this.delayMillis = delayMillis;
  }

  private <T> CompletableFuture<T> later(java.util.function.Supplier<T> body) {
    calls.incrementAndGet();
    return CompletableFuture.supplyAsync(() -> {
      try {
        TimeUnit.MILLISECONDS.sleep(delayMillis); // stands in for the network round trip
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
      return body.get();
    }, completer);
  }

  private byte[] wrap(byte[] plaintext) {
    byte[] ciphertext = new byte[48];
    random.nextBytes(ciphertext);
    store.put(ByteBuffer.wrap(ciphertext), plaintext.clone());
    return ciphertext;
  }

  @Override
  public CompletableFuture<GenerateDataKeyResponse> generateDataKey(GenerateDataKeyRequest r) {
    return later(() -> {
      byte[] plaintext = new byte[r.numberOfBytes()];
      random.nextBytes(plaintext);
      return GenerateDataKeyResponse.builder().keyId(r.keyId()).plaintext(SdkBytes.fromByteArray(plaintext))
          .ciphertextBlob(SdkBytes.fromByteArray(wrap(plaintext))).build();
    });
  }

  @Override
  public CompletableFuture<EncryptResponse> encrypt(EncryptRequest r) {
    return later(() -> EncryptResponse.builder().keyId(r.keyId())
        .ciphertextBlob(SdkBytes.fromByteArray(wrap(r.plaintext().asByteArray()))).build());
  }

  @Override
  public CompletableFuture<DecryptResponse> decrypt(DecryptRequest r) {
    return later(() -> {
      byte[] plaintext = store.get(ByteBuffer.wrap(r.ciphertextBlob().asByteArray()));
      if (plaintext == null) {
        // The SDK delivers service errors as the future's cause (a CompletionException wrapper when joined).
        throw InvalidCiphertextException.builder().message("stub: unknown ciphertext").build();
      }
      return DecryptResponse.builder().keyId(r.keyId()).plaintext(SdkBytes.fromByteArray(plaintext)).build();
    });
  }

  @Override
  public String serviceName() {
    return "kms";
  }

  @Override
  public void close() {
    completer.shutdown();
  }
}
