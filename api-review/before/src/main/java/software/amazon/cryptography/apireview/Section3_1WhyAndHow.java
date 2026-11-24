// Section 3.1 of the API review doc: Why and how
// Before: the Dafny-based MPL 1.11.1, with ESDK 3.0.2 and DB-ESDK 3.3.0.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsKeyringInput;
import software.amazon.cryptography.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.model.OnDecryptInput;
import software.amazon.cryptography.materialproviders.model.OnDecryptOutput;
import software.amazon.cryptography.materialproviders.model.OnEncryptInput;
import software.amazon.cryptography.materialproviders.model.OnEncryptOutput;

final class Section3_1WhyAndHow {
  private Section3_1WhyAndHow() {}

  // 3.1: Two interfaces, one set of requests and responses
  static CompletableFuture<?> twoInterfaces(MaterialProviders mpl, String keyArn, KmsClient kmsClient,
      OnEncryptInput input, Executor pool) {
    // @card 31-twoifaces
    IKeyring keyring = mpl.CreateAwsKmsKeyring(
        CreateAwsKmsKeyringInput.builder().kmsKeyId(keyArn).kmsClient(kmsClient).build());
    // The keyring is sync, so a pool thread runs OnEncrypt and waits for KMS.
    CompletableFuture<OnEncryptOutput> encrypted =
        CompletableFuture.supplyAsync(() -> keyring.OnEncrypt(input), pool);
    // @end
    return encrypted;
  }

  // 3.1: Twins only for what does I/O
  static void twins(IKeyring kmsKeyring, IKeyring rawAesKeyring, OnEncryptInput input, Executor pool) {
    // @card 31-twins
    // Each keyring takes a pool thread, whether it calls KMS or only computes.
    CompletableFuture<OnEncryptOutput> kms = CompletableFuture.supplyAsync(() -> kmsKeyring.OnEncrypt(input), pool);
    CompletableFuture<OnEncryptOutput> aes = CompletableFuture.supplyAsync(() -> rawAesKeyring.OnEncrypt(input), pool);
    // @end
    kms.join();
    aes.join();
  }

  // 3.1: Neither flavor wraps the other
  static CompletableFuture<OnDecryptOutput> noWrap(IKeyring keyring, OnEncryptInput encryptInput,
      DecryptionMaterials decryptionMaterials, Executor pool) {
    // @card 31-nowrap
    // Each step holds a pool thread while it waits for KMS.
    CompletableFuture<OnDecryptOutput> roundTrip = CompletableFuture
        .supplyAsync(() -> keyring.OnEncrypt(encryptInput), pool)
        .thenApplyAsync(encrypted -> keyring.OnDecrypt(OnDecryptInput.builder()
            .materials(decryptionMaterials)
            .encryptedDataKeys(encrypted.materials().encryptedDataKeys())
            .build()), pool);
    // @end
    return roundTrip;
  }

  // 3.1: The rejected shapes: async only, or one type with both
  // @card 31-rejected
  // One type with both flavors: which path is real does not show in the type.
  static final class EitherKeyring {
    // ... the fields keyring (an IKeyring) and pool (an Executor), set by the constructor
    // @hide
    private final IKeyring keyring;
    private final Executor pool;

    EitherKeyring(IKeyring keyring, Executor pool) {
      this.keyring = keyring;
      this.pool = pool;
    }

    // @show
    OnEncryptOutput onEncrypt(OnEncryptInput input) {
      return keyring.OnEncrypt(input);
    }

    CompletableFuture<OnEncryptOutput> onEncryptAsync(OnEncryptInput input) {
      return CompletableFuture.supplyAsync(() -> keyring.OnEncrypt(input), pool);
    }
  }
  // @end
}
