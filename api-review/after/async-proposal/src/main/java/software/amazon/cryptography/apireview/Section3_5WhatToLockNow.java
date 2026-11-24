// Section 3.5 of the API review doc: What 2.0.0 must lock now
// After (proposal): the async API, on the async spike and the proposal stubs.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.util.concurrent.CompletableFuture;
import proposal.KmsAsyncClientSupplier;
import proposal.KmsClientSupplier;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.ClientSupplier;
import spike.AsyncKeyring;

final class Section3_5WhatToLockNow {
  private Section3_5WhatToLockNow() {}

  // 3.5: Reserve the async names, in the same packages
  static Keyring clientSupplierToday(String keyArn1, String keyArn2) {
    // @card 35-names as before
    ClientSupplier supplier = region -> KmsClient.builder().region(Region.of(region)).build();
    AwsKmsMultiKeyring keyring = AwsKmsMultiKeyring.builder()
        .generator(keyArn1).kmsKeyIds(keyArn2).clientSupplier(supplier).build();
    // @end
    return keyring;
  }

  // 3.5: Reserve the async names, in the same packages
  static Object[] clientSupplierRenamed() {
    // @card 35-names
    // If renamed before 2.0.0, the async twin's name follows it.
    KmsClientSupplier supplier = region -> KmsClient.builder().region(Region.of(region)).build();
    KmsAsyncClientSupplier asyncSupplier = region -> KmsAsyncClient.builder().region(Region.of(region)).build();
    // @end
    return new Object[] {supplier, asyncSupplier};
  }

  // 3.5: Keep requests free of threads, and document the contracts
  static CompletableFuture<OnEncryptResponse> sameRequest(Keyring syncKeyring, AsyncKeyring asyncKeyring,
      EncryptionMaterials materials) {
    // @card 35-requests
    // The request holds only the materials: no client, executor, or thread context.
    OnEncryptRequest request = OnEncryptRequest.builder().materials(materials).build();
    OnEncryptResponse now = syncKeyring.onEncrypt(request);
    CompletableFuture<OnEncryptResponse> later = asyncKeyring.onEncrypt(request);
    // @end
    now.hashCode();
    return later;
  }
}
