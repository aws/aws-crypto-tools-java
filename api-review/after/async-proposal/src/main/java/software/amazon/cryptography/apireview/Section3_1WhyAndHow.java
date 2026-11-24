// Section 3.1 of the API review doc: Why and how
// After (proposal): the async API, on the async spike and the proposal stubs.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.util.concurrent.CompletableFuture;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnDecryptResponse;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsKeyring;
import spike.AsyncKeyring;
import spike.AsyncKeyrings;
import spike.AwsKmsAsyncKeyring;

final class Section3_1WhyAndHow {
  private Section3_1WhyAndHow() {}

  // 3.1: Two interfaces, one set of requests and responses
  static CompletableFuture<EncryptionMaterials> twoInterfaces(String keyArn, KmsAsyncClient kmsAsyncClient,
      OnEncryptRequest request) {
    // @card 31-twoifaces
    AsyncKeyring keyring = AwsKmsAsyncKeyring.builder().kmsKeyId(keyArn).kmsClient(kmsAsyncClient).build();
    // The same OnEncryptRequest as the sync Keyring takes; the call returns a future at once.
    CompletableFuture<OnEncryptResponse> encrypted = keyring.onEncrypt(request);
    // @end
    return encrypted.thenApply(OnEncryptResponse::materials);
  }

  // 3.1: Twins only for what does I/O
  static void twins(String keyArn, KmsAsyncClient kmsAsyncClient, Keyring rawAesKeyring, OnEncryptRequest request) {
    // @card 31-twins
    // A twin for the keyring that calls KMS; the raw AES keyring, which only computes, goes through an adapter
    // (AsyncKeyring.fromNonBlocking in the proposal, AsyncKeyrings in the spike).
    AsyncKeyring kmsKeyring = AwsKmsAsyncKeyring.builder().kmsKeyId(keyArn).kmsClient(kmsAsyncClient).build();
    AsyncKeyring aesKeyring = AsyncKeyrings.fromNonBlocking(rawAesKeyring);
    CompletableFuture<OnEncryptResponse> kms = kmsKeyring.onEncrypt(request);
    CompletableFuture<OnEncryptResponse> aes = aesKeyring.onEncrypt(request);
    // @end
    kms.join();
    aes.join();
  }

  // 3.1: Neither flavor wraps the other
  static CompletableFuture<OnDecryptResponse> noWrap(AsyncKeyring keyring, OnEncryptRequest encryptRequest,
      DecryptionMaterials decryptionMaterials) {
    // @card 31-nowrap
    // Each step returns at once; the KMS response completes the future, and no thread waits.
    CompletableFuture<OnDecryptResponse> roundTrip = keyring
        .onEncrypt(encryptRequest)
        .thenCompose(encrypted -> keyring.onDecrypt(OnDecryptRequest.builder()
            .materials(decryptionMaterials)
            .encryptedDataKeys(encrypted.materials().encryptedDataKeys())
            .build()));
    // @end
    return roundTrip;
  }

  // 3.1: The rejected shapes: async only, or one type with both
  static CompletableFuture<OnEncryptResponse> rejected(String keyArn, KmsClient kmsClient,
      KmsAsyncClient kmsAsyncClient, OnEncryptRequest request) {
    // @card 31-rejected
    // One class per flavor, with the same builder members and method names.
    Keyring syncKeyring = AwsKmsKeyring.builder().kmsKeyId(keyArn).kmsClient(kmsClient).build();
    AsyncKeyring asyncKeyring = AwsKmsAsyncKeyring.builder().kmsKeyId(keyArn).kmsClient(kmsAsyncClient).build();
    OnEncryptResponse now = syncKeyring.onEncrypt(request);
    CompletableFuture<OnEncryptResponse> later = asyncKeyring.onEncrypt(request);
    // @end
    now.hashCode();
    return later;
  }
}
