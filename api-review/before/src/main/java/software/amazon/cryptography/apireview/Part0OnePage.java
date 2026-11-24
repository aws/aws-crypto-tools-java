// Part 0 of the API review doc: What changes, on one page
// Before: the Dafny-based MPL 1.11.1, with ESDK 3.0.2 and DB-ESDK 3.3.0.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import com.amazonaws.encryptionsdk.AwsCrypto;
import java.util.Map;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.CreateKeyInput;
import software.amazon.cryptography.keystore.model.GetActiveBranchKeyInput;
import software.amazon.cryptography.keystore.model.KMSConfiguration;
import software.amazon.cryptography.keystore.model.KeyStoreConfig;
import software.amazon.cryptography.keystore.model.KeyStoreException;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.AwsCryptographicMaterialProvidersException;
import software.amazon.cryptography.materialproviders.model.CacheType;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsHierarchicalKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateDefaultCryptographicMaterialsManagerInput;
import software.amazon.cryptography.materialproviders.model.DefaultCache;
import software.amazon.cryptography.materialproviders.model.ESDKAlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.model.GetEncryptionMaterialsOutput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;
import software.amazon.cryptography.materialproviders.model.OnDecryptInput;
import software.amazon.cryptography.materialproviders.model.OnDecryptOutput;
import software.amazon.cryptography.materialproviders.model.OnEncryptInput;
import software.amazon.cryptography.materialproviders.model.OnEncryptOutput;

final class Part0OnePage {
  private Part0OnePage() {}

  // Part 0: 1. Keyrings build themselves
  static ICryptographicMaterialsManager p0Build(String keyArn, KmsClient kmsClient) {
    // @card 0-build
    MaterialProviders mpl = MaterialProviders.builder()
        .MaterialProvidersConfig(MaterialProvidersConfig.builder().build()).build();
    IKeyring keyring = mpl.CreateAwsKmsKeyring(
        CreateAwsKmsKeyringInput.builder().kmsKeyId(keyArn).kmsClient(kmsClient).build());
    // ... cmm: mpl.CreateDefaultCryptographicMaterialsManager(...), with an input that holds the keyring
    // @hide
    ICryptographicMaterialsManager cmm = mpl.CreateDefaultCryptographicMaterialsManager(
        CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(keyring).build());
    // @show
    // @end
    return cmm;
  }

  // Part 0: 2. Operations take a request and return a response
  static final class P0Keyring implements IKeyring {
    // @card 0-request
    @Override
    public OnEncryptOutput OnEncrypt(OnEncryptInput input) {
      EncryptionMaterials wrapped = addEncryptedDataKey(input.materials());
      return OnEncryptOutput.builder().materials(wrapped).build();
    }
    // @end

    @Override
    public OnDecryptOutput OnDecrypt(OnDecryptInput input) {
      return OnDecryptOutput.builder().materials(input.materials()).build();
    }

    private static EncryptionMaterials addEncryptedDataKey(EncryptionMaterials materials) {
      return materials;
    }
  }

  // Part 0: 3. The key store is `DynamoDbKeyStore`, behind a `KeyStore` interface
  static String p0KeyStore(String tableName, String logicalKeyStoreName, String kmsKeyArn) {
    // @card 0-keystore
    KeyStore keyStore = KeyStore.builder().KeyStoreConfig(KeyStoreConfig.builder()
        .ddbTableName(tableName).logicalKeyStoreName(logicalKeyStoreName)
        .kmsConfiguration(KMSConfiguration.builder().kmsKeyArn(kmsKeyArn).build()).build()).build();
    String branchKeyId = keyStore.CreateKey(CreateKeyInput.builder().build()).branchKeyIdentifier();
    // @end
    return branchKeyId;
  }

  // Part 0: 4. Caches are objects
  static IKeyring p0Cache(MaterialProviders mpl, KeyStore keyStore, String branchKeyId) {
    // @card 0-cache
    IKeyring keyring = mpl.CreateAwsKmsHierarchicalKeyring(CreateAwsKmsHierarchicalKeyringInput.builder()
        .keyStore(keyStore).branchKeyId(branchKeyId).ttlSeconds(600)
        .cache(CacheType.builder().Default(DefaultCache.builder().entryCapacity(100).build()).build())
        .build());
    // @end
    return keyring;
  }

  // Part 0: 5. One suite enum per message format
  static boolean p0Suite(GetEncryptionMaterialsOutput output) {
    // @card 0-suite
    AlgorithmSuiteId suite = AlgorithmSuiteId.builder()
        .ESDK(ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY).build();
    boolean signing = output.encryptionMaterials().algorithmSuite().signature().ECDSA() != null;
    // @end
    return signing && suite != null;
  }

  // Part 0: 8. ESDK calls in SDK style (proposal)
  static byte[] p0Esdk(IKeyring keyring, byte[] plaintext, Map<String, String> encryptionContext) {
    // @card 0-esdk
    AwsCrypto crypto = AwsCrypto.builder().build();
    byte[] ciphertext = crypto.encryptData(keyring, plaintext, encryptionContext).getResult();
    byte[] decrypted = crypto.decryptData(keyring, ciphertext, encryptionContext).getResult();
    // @end
    return decrypted;
  }

  // Part 0: 6. One exception family
  static String p0Errors(KeyStore keyStore, String branchKeyId) {
    // @card 0-errors
    try {
      keyStore.GetActiveBranchKey(GetActiveBranchKeyInput.builder().branchKeyIdentifier(branchKeyId).build());
    } catch (AwsServiceException e) {
      return e.retryable() || e.isThrottlingException() ? "retry later" : "AWS call failed: " + e.getMessage();
    // @hide
    } catch (KeyStoreException | AwsCryptographicMaterialProvidersException e) {
      return "failed: " + e.getMessage();
    // @show
    } // ... then catch KeyStoreException | AwsCryptographicMaterialProvidersException: "failed: " + message
    // @end
    return "ok";
  }
}
