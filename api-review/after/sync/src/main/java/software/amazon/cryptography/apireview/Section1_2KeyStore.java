// Section 1.2 of the API review doc: Key store
// After: the native MPL 2.0.0, with the ESDK 4.0 sketch and the DB-ESDK stand-ins (proposals).
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;
import software.amazon.cryptography.materialproviders.keystore.BranchKeyMaterials;
import software.amazon.cryptography.materialproviders.keystore.DynamoDbKeyStore;
import software.amazon.cryptography.materialproviders.keystore.GetActiveBranchKeyRequest;
import software.amazon.cryptography.materialproviders.keystore.GetActiveBranchKeyResponse;
import software.amazon.cryptography.materialproviders.keystore.GetBeaconKeyRequest;
import software.amazon.cryptography.materialproviders.keystore.GetBeaconKeyResponse;
import software.amazon.cryptography.materialproviders.keystore.GetBranchKeyVersionRequest;
import software.amazon.cryptography.materialproviders.keystore.GetBranchKeyVersionResponse;
import software.amazon.cryptography.materialproviders.keystore.GetKeyStoreInfoRequest;
import software.amazon.cryptography.materialproviders.keystore.GetKeyStoreInfoResponse;
import software.amazon.cryptography.materialproviders.keystore.KeyStore;
import software.amazon.cryptography.materialproviders.keystore.KmsConfiguration;

final class Section1_2KeyStore {
  private Section1_2KeyStore() {}

  // 1.2: DynamoDbKeyStore builds itself
  static DynamoDbKeyStore keyStore(String tableName, String logicalKeyStoreName, String kmsKeyArn,
      KmsClient kmsClient, DynamoDbClient ddbClient) {
    // @card 12-keystore
    DynamoDbKeyStore keyStore = DynamoDbKeyStore.builder()
        .ddbTableName(tableName)
        .logicalKeyStoreName(logicalKeyStoreName)
        .kmsConfiguration(KmsConfiguration.kmsKeyArn(kmsKeyArn))
        .kmsClient(kmsClient)
        .ddbClient(ddbClient)
        .build();
    keyStore.createKeyStore();
    // @end
    return keyStore;
  }

  // 1.2: KMS configuration comes from factories
  static DynamoDbKeyStore kmsConfigurations(String tableName, String logicalKeyStoreName, String kmsKeyArn,
      String mrkArn) {
    // @card 12-kmsconfig
    KmsConfiguration singleKey = KmsConfiguration.kmsKeyArn(kmsKeyArn);
    KmsConfiguration multiRegionKey = KmsConfiguration.kmsMrKeyArn(mrkArn);
    KmsConfiguration discovery = KmsConfiguration.discovery();
    KmsConfiguration mrDiscovery = KmsConfiguration.mrDiscovery("us-west-2");
    DynamoDbKeyStore readOnly = DynamoDbKeyStore.builder()
        .ddbTableName(tableName).logicalKeyStoreName(logicalKeyStoreName).kmsConfiguration(discovery)
        .build();
    // @end
    java.util.Arrays.asList(singleKey, multiRegionKey, mrDiscovery).hashCode();
    return readOnly;
  }

  // 1.2: Operations take a request, or a lambda
  static String operations(DynamoDbKeyStore keyStore, String branchKeyId) {
    // @card 12-ops
    keyStore.versionKey(b -> b.branchKeyId(branchKeyId));
    GetActiveBranchKeyResponse active = keyStore.getActiveBranchKey(
        GetActiveBranchKeyRequest.builder().branchKeyId(branchKeyId).build());
    String version = active.branchKeyMaterials().branchKeyVersion();
    GetKeyStoreInfoResponse info = keyStore.getKeyStoreInfo();
    // @end
    return version + info.keyStoreId();
  }

  // 1.2: The key store is an interface you can implement
  static Keyring customKeyStore(DynamoDbKeyStore dynamoDbKeyStore, String branchKeyId) {
    // @card 12-iface
    final class CountingKeyStore implements KeyStore {
      // ... delegate: the DynamoDbKeyStore it wraps; reads: an AtomicLong
      // @hide
      private final KeyStore delegate = dynamoDbKeyStore;
      private final AtomicLong reads = new AtomicLong();
      // @show
      @Override
      public GetActiveBranchKeyResponse getActiveBranchKey(GetActiveBranchKeyRequest request) {
        reads.incrementAndGet();
        return delegate.getActiveBranchKey(request);
      }
      // ... getBranchKeyVersion counts the same way; getBeaconKey and getKeyStoreInfo return the delegate's
      // @hide
      @Override
      public GetBranchKeyVersionResponse getBranchKeyVersion(GetBranchKeyVersionRequest request) {
        reads.incrementAndGet();
        return delegate.getBranchKeyVersion(request);
      }

      @Override
      public GetBeaconKeyResponse getBeaconKey(GetBeaconKeyRequest request) {
        return delegate.getBeaconKey(request);
      }

      @Override
      public GetKeyStoreInfoResponse getKeyStoreInfo(GetKeyStoreInfoRequest request) {
        return delegate.getKeyStoreInfo(request);
      }
      // @show
    }
    AwsKmsHierarchicalKeyring keyring = AwsKmsHierarchicalKeyring.builder()
        .keyStore(new CountingKeyStore()).branchKeyId(branchKeyId).ttl(Duration.ofMinutes(10)).build();
    // @end
    return keyring;
  }

  // 1.2: branchKeyId everywhere
  static String branchKeyIds(DynamoDbKeyStore keyStore) {
    // @card 12-branchkeyid
    String branchKeyId = keyStore.createKey().branchKeyId();
    BranchKeyMaterials materials =
        keyStore.getActiveBranchKey(b -> b.branchKeyId(branchKeyId)).branchKeyMaterials();
    String sameId = materials.branchKeyId();
    String beaconKeyId = keyStore.getBeaconKey(b -> b.branchKeyId(branchKeyId))
        .beaconKeyMaterials().beaconKeyIdentifier();
    // @end
    return sameId + beaconKeyId;
  }
}
