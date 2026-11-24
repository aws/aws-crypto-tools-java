// Section 1.2 of the API review doc: Key store
// Before: the Dafny-based MPL 1.11.1, with ESDK 3.0.2 and DB-ESDK 3.3.0.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.util.Arrays;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.BranchKeyMaterials;
import software.amazon.cryptography.keystore.model.CreateKeyInput;
import software.amazon.cryptography.keystore.model.CreateKeyStoreInput;
import software.amazon.cryptography.keystore.model.Discovery;
import software.amazon.cryptography.keystore.model.GetActiveBranchKeyInput;
import software.amazon.cryptography.keystore.model.GetActiveBranchKeyOutput;
import software.amazon.cryptography.keystore.model.GetBeaconKeyInput;
import software.amazon.cryptography.keystore.model.GetKeyStoreInfoOutput;
import software.amazon.cryptography.keystore.model.KMSConfiguration;
import software.amazon.cryptography.keystore.model.KeyStoreConfig;
import software.amazon.cryptography.keystore.model.MRDiscovery;
import software.amazon.cryptography.keystore.model.VersionKeyInput;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsHierarchicalKeyringInput;

final class Section1_2KeyStore {
  private Section1_2KeyStore() {}

  // 1.2: DynamoDbKeyStore builds itself
  static KeyStore keyStore(String tableName, String logicalKeyStoreName, String kmsKeyArn, KmsClient kmsClient,
      DynamoDbClient ddbClient) {
    // @card 12-keystore
    KeyStore keyStore = KeyStore.builder()
        .KeyStoreConfig(KeyStoreConfig.builder()
            .ddbTableName(tableName)
            .logicalKeyStoreName(logicalKeyStoreName)
            .kmsConfiguration(KMSConfiguration.builder().kmsKeyArn(kmsKeyArn).build())
            .kmsClient(kmsClient)
            .ddbClient(ddbClient)
            .build())
        .build();
    keyStore.CreateKeyStore(CreateKeyStoreInput.builder().build());
    // @end
    return keyStore;
  }

  // 1.2: KMS configuration comes from factories
  static KeyStore kmsConfigurations(String tableName, String logicalKeyStoreName, String kmsKeyArn, String mrkArn) {
    // @card 12-kmsconfig
    KMSConfiguration singleKey = KMSConfiguration.builder().kmsKeyArn(kmsKeyArn).build();
    KMSConfiguration multiRegionKey = KMSConfiguration.builder().kmsMRKeyArn(mrkArn).build();
    KMSConfiguration discovery = KMSConfiguration.builder().discovery(Discovery.builder().build()).build();
    KMSConfiguration mrDiscovery =
        KMSConfiguration.builder().mrDiscovery(MRDiscovery.builder().region("us-west-2").build()).build();
    KeyStore readOnly = KeyStore.builder()
        .KeyStoreConfig(KeyStoreConfig.builder()
            .ddbTableName(tableName).logicalKeyStoreName(logicalKeyStoreName).kmsConfiguration(discovery).build())
        .build();
    // @end
    Arrays.asList(singleKey, multiRegionKey, mrDiscovery).hashCode();
    return readOnly;
  }

  // 1.2: Operations take a request, or a lambda
  static String operations(KeyStore keyStore, String branchKeyId) {
    // @card 12-ops
    keyStore.VersionKey(VersionKeyInput.builder().branchKeyIdentifier(branchKeyId).build());
    GetActiveBranchKeyOutput active = keyStore.GetActiveBranchKey(
        GetActiveBranchKeyInput.builder().branchKeyIdentifier(branchKeyId).build());
    String version = active.branchKeyMaterials().branchKeyVersion();
    GetKeyStoreInfoOutput info = keyStore.GetKeyStoreInfo();
    // @end
    return version + info.keyStoreId();
  }

  // 1.2: The key store is an interface you can implement
  static IKeyring onlyTheGeneratedKeyStore(MaterialProviders mpl, KeyStoreConfig config, String branchKeyId) {
    // @card 12-iface
    // The keyring takes the generated KeyStore class, which runs the Dafny DynamoDB key store,
    // so there is no key store of your own to pass in.
    KeyStore keyStore = KeyStore.builder().KeyStoreConfig(config).build();
    IKeyring keyring = mpl.CreateAwsKmsHierarchicalKeyring(CreateAwsKmsHierarchicalKeyringInput.builder()
        .keyStore(keyStore).branchKeyId(branchKeyId).ttlSeconds(600).build());
    // @end
    return keyring;
  }

  // 1.2: branchKeyId everywhere
  static String branchKeyIds(KeyStore keyStore) {
    // @card 12-branchkeyid
    String branchKeyId = keyStore.CreateKey(CreateKeyInput.builder().build()).branchKeyIdentifier();
    BranchKeyMaterials materials = keyStore.GetActiveBranchKey(
        GetActiveBranchKeyInput.builder().branchKeyIdentifier(branchKeyId).build()).branchKeyMaterials();
    String sameId = materials.branchKeyIdentifier();
    String beaconKeyId = keyStore.GetBeaconKey(GetBeaconKeyInput.builder().branchKeyIdentifier(branchKeyId).build())
        .beaconKeyMaterials().beaconKeyIdentifier();
    // @end
    return sameId + beaconKeyId;
  }
}
