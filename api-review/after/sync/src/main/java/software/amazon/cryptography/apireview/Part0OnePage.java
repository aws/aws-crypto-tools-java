// Part 0 of the API review doc: What changes, on one page
// After: the native MPL 2.0.0, with the ESDK 4.0 sketch and the DB-ESDK stand-ins (proposals).
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.time.Duration;
import java.util.Map;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsResponse;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnDecryptResponse;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;
import software.amazon.cryptography.materialproviders.cache.DefaultCache;
import software.amazon.cryptography.materialproviders.cmm.DefaultCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.exceptions.MaterialProvidersException;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsKeyring;
import software.amazon.cryptography.materialproviders.keystore.DynamoDbKeyStore;
import software.amazon.cryptography.materialproviders.keystore.KeyStore;
import software.amazon.cryptography.materialproviders.keystore.KmsConfiguration;

final class Part0OnePage {
  private Part0OnePage() {}

  // Part 0: 1. Keyrings build themselves
  static CryptographicMaterialsManager p0Build(String keyArn, KmsClient kmsClient) {
    // @card 0-build
    AwsKmsKeyring keyring = AwsKmsKeyring.builder().kmsKeyId(keyArn).kmsClient(kmsClient).build();
    DefaultCryptographicMaterialsManager cmm = DefaultCryptographicMaterialsManager.create(keyring);
    // @end
    return cmm;
  }

  // Part 0: 2. Operations take a request and return a response
  static final class P0Keyring implements Keyring {
    // @card 0-request
    @Override
    public OnEncryptResponse onEncrypt(OnEncryptRequest request) {
      EncryptionMaterials wrapped = addEncryptedDataKey(request.materials());
      return OnEncryptResponse.builder().materials(wrapped).build();
    }
    // @end

    @Override
    public OnDecryptResponse onDecrypt(OnDecryptRequest request) {
      return OnDecryptResponse.builder().materials(request.materials()).build();
    }

    private static EncryptionMaterials addEncryptedDataKey(EncryptionMaterials materials) {
      return materials;
    }
  }

  // Part 0: 3. The key store is `DynamoDbKeyStore`, behind a `KeyStore` interface
  static String p0KeyStore(String tableName, String logicalKeyStoreName, String kmsKeyArn) {
    // @card 0-keystore
    DynamoDbKeyStore keyStore = DynamoDbKeyStore.builder()
        .ddbTableName(tableName).logicalKeyStoreName(logicalKeyStoreName)
        .kmsConfiguration(KmsConfiguration.kmsKeyArn(kmsKeyArn)).build();
    String branchKeyId = keyStore.createKey().branchKeyId();
    // @end
    return branchKeyId;
  }

  // Part 0: 4. Caches are objects
  static Keyring p0Cache(DynamoDbKeyStore keyStore, String branchKeyId) {
    // @card 0-cache
    AwsKmsHierarchicalKeyring keyring = AwsKmsHierarchicalKeyring.builder()
        .keyStore(keyStore).branchKeyId(branchKeyId).ttl(Duration.ofMinutes(10))
        .cache(DefaultCache.builder().entryCapacity(100).build())
        .build();
    // @end
    return keyring;
  }

  // Part 0: 5. One suite enum per message format
  static boolean p0Suite(GetEncryptionMaterialsResponse response) {
    // @card 0-suite
    EsdkAlgorithmSuite suite = EsdkAlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
    boolean signing = response.encryptionMaterials().algorithmSuite().isSigning();
    // @end
    return signing && suite != null;
  }

  // Part 0: 8. ESDK calls in SDK style (proposal)
  static byte[] p0Esdk(Keyring keyring, byte[] plaintext, Map<String, String> encryptionContext) {
    // @card 0-esdk
    EsdkClient esdk = EsdkClient.create();
    byte[] ciphertext = esdk.encrypt(b -> b
        .plaintext(plaintext).keyring(keyring).encryptionContext(encryptionContext)).ciphertext();
    byte[] decrypted = esdk.decrypt(b -> b
        .ciphertext(ciphertext).keyring(keyring).encryptionContext(encryptionContext)).plaintext();
    // @end
    return decrypted;
  }

  // Part 0: 6. One exception family
  static String p0Errors(DynamoDbKeyStore keyStore, String branchKeyId) {
    // @card 0-errors
    try {
      keyStore.getActiveBranchKey(b -> b.branchKeyId(branchKeyId));
    } catch (MaterialProvidersException e) {
      return e.isRetryable() ? "retry later" : e.kind() + " failed: " + e.getMessage();
    }
    // @end
    return "ok";
  }
}
