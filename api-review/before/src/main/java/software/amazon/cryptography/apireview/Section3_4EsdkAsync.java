// Section 3.4 of the API review doc: ESDK async
// Before: the Dafny-based MPL 1.11.1, with ESDK 3.0.2 and DB-ESDK 3.3.0.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsKeyringInput;

final class Section3_4EsdkAsync {
  private Section3_4EsdkAsync() {}

  // 3.4: EsdkAsyncClient takes the same requests
  static CompletableFuture<byte[]> esdkAsync(AwsCrypto crypto, IKeyring keyring, byte[] plaintext,
      Map<String, String> encryptionContext, Executor pool) {
    // @card 34-client
    CompletableFuture<byte[]> ciphertext = CompletableFuture.supplyAsync(
        () -> crypto.encryptData(keyring, plaintext, encryptionContext).getResult(), pool);
    CompletableFuture<byte[]> decrypted = ciphertext.thenApplyAsync(
        c -> crypto.decryptData(keyring, c).getResult(), pool);
    // @end
    return decrypted;
  }

  // 3.4: Async materials go only to the async client
  static CompletableFuture<byte[]> materials(MaterialProviders mpl, AwsCrypto crypto, String keyArn,
      KmsClient kmsClient, byte[] plaintext, Executor pool) {
    // @card 34-materials
    // AwsCrypto takes only sync keyrings, and the application picks the thread.
    IKeyring keyring = mpl.CreateAwsKmsKeyring(
        CreateAwsKmsKeyringInput.builder().kmsKeyId(keyArn).kmsClient(kmsClient).build());
    CompletableFuture<byte[]> ciphertext =
        CompletableFuture.supplyAsync(() -> crypto.encryptData(keyring, plaintext).getResult(), pool);
    // @end
    return ciphertext;
  }

  // 3.4: Where the CPU work runs
  static CompletableFuture<byte[]> cpu(AwsCrypto crypto, IKeyring keyring, byte[] plaintext,
      Map<String, String> encryptionContext) {
    // @card 34-cpu
    // A pool sized for blocking calls: each thread waits for KMS, then encrypts the frames.
    ExecutorService pool = Executors.newFixedThreadPool(16);
    CompletableFuture<byte[]> ciphertext = CompletableFuture.supplyAsync(
        () -> crypto.encryptData(keyring, plaintext, encryptionContext).getResult(), pool);
    // @end
    return ciphertext;
  }

  // 3.4: Streaming later, with Reactive Streams
  static CompletableFuture<Void> streaming(AwsCrypto crypto, IKeyring keyring, byte[] plaintext,
      Map<String, String> encryptionContext, OutputStream outputStream, Executor pool) {
    // @card 34-streaming
    CompletableFuture<Void> done = CompletableFuture.runAsync(() -> {
      try (CryptoOutputStream<?> encrypting =
          crypto.createEncryptingStream(keyring, outputStream, encryptionContext)) {
        encrypting.write(plaintext);
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
    }, pool);
    // @end
    return done;
  }
}
