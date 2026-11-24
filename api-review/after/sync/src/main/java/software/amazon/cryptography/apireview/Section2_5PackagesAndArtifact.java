// Section 2.5 of the API review doc: Packages and artifact
// After: the native MPL 2.0.0, with the ESDK 4.0 sketch and the DB-ESDK stand-ins (proposals).
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.cache.DefaultCache;
import software.amazon.cryptography.materialproviders.cmm.DefaultCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsKeyring;
import software.amazon.cryptography.materialproviders.keystore.CreateKeyResponse;
import software.amazon.cryptography.materialproviders.keystore.DynamoDbKeyStore;

final class Section2_5PackagesAndArtifact {
  private Section2_5PackagesAndArtifact() {}

  // 2.5: No factory client
  static CryptographicMaterialsManager noFactory(String keyArn, KmsClient kmsClient) {
    // @card 25-nofactory
    AwsKmsKeyring keyring = AwsKmsKeyring.builder().kmsKeyId(keyArn).kmsClient(kmsClient).build();
    DefaultCryptographicMaterialsManager cmm = DefaultCryptographicMaterialsManager.create(keyring);
    DefaultCache cache = DefaultCache.builder().entryCapacity(100).build();
    // @end
    cache.hashCode();
    return cmm;
  }

  // 2.5: One subpackage per area
  static void packages(DynamoDbKeyStore keyStore, String keyArn, KmsClient kmsClient) {
    // @card 25-packages
    software.amazon.cryptography.materialproviders.keyrings.AwsKmsKeyring keyring =
        software.amazon.cryptography.materialproviders.keyrings.AwsKmsKeyring.builder()
            .kmsKeyId(keyArn).kmsClient(kmsClient).build();
    software.amazon.cryptography.materialproviders.cmm.DefaultCryptographicMaterialsManager cmm =
        software.amazon.cryptography.materialproviders.cmm.DefaultCryptographicMaterialsManager.create(keyring);
    software.amazon.cryptography.materialproviders.keystore.CreateKeyResponse created =
        keyStore.createKey();
    // @end
    cmm.hashCode();
    created.hashCode();
  }
}
