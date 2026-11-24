// Section 2.5 of the API review doc: Packages and artifact
// Before: the Dafny-based MPL 1.11.1, with ESDK 3.0.2 and DB-ESDK 3.3.0.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.CreateKeyInput;
import software.amazon.cryptography.keystore.model.CreateKeyOutput;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CacheType;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateDefaultCryptographicMaterialsManagerInput;
import software.amazon.cryptography.materialproviders.model.DefaultCache;

final class Section2_5PackagesAndArtifact {
  private Section2_5PackagesAndArtifact() {}

  // 2.5: No factory client
  static ICryptographicMaterialsManager noFactory(String keyArn, KmsClient kmsClient) {
    // @card 25-nofactory
    MaterialProviders mpl = MaterialProviders.builder()
        .MaterialProvidersConfig(
            software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig.builder().build())
        .build();
    IKeyring keyring = mpl.CreateAwsKmsKeyring(
        CreateAwsKmsKeyringInput.builder().kmsKeyId(keyArn).kmsClient(kmsClient).build());
    ICryptographicMaterialsManager cmm = mpl.CreateDefaultCryptographicMaterialsManager(
        CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(keyring).build());
    CacheType cache = CacheType.builder().Default(DefaultCache.builder().entryCapacity(100).build()).build();
    // @end
    cache.hashCode();
    return cmm;
  }

  // 2.5: One subpackage per area
  static void packages(MaterialProviders mpl, KeyStore keyStore, String keyArn, KmsClient kmsClient) {
    // @card 25-packages
    software.amazon.cryptography.materialproviders.IKeyring keyring = mpl.CreateAwsKmsKeyring(
        software.amazon.cryptography.materialproviders.model.CreateAwsKmsKeyringInput.builder()
            .kmsKeyId(keyArn).kmsClient(kmsClient).build());
    software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager cmm =
        mpl.CreateDefaultCryptographicMaterialsManager(
            software.amazon.cryptography.materialproviders.model.CreateDefaultCryptographicMaterialsManagerInput
                .builder().keyring(keyring).build());
    software.amazon.cryptography.keystore.model.CreateKeyOutput created =
        keyStore.CreateKey(software.amazon.cryptography.keystore.model.CreateKeyInput.builder().build());
    // @end
    cmm.hashCode();
    created.hashCode();
  }
}
