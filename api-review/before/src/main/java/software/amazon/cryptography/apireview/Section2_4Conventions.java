// Section 2.4 of the API review doc: Conventions
// Before: the Dafny-based MPL 1.11.1, with ESDK 3.0.2 and DB-ESDK 3.3.0.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import com.amazonaws.encryptionsdk.AwsCrypto;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.CreateKeyInput;
import software.amazon.cryptography.keystore.model.CreateKeyOutput;
import software.amazon.cryptography.keystore.model.KMSConfiguration;
import software.amazon.cryptography.keystore.model.KeyStoreConfig;
import software.amazon.cryptography.materialproviders.IClientSupplier;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsHierarchicalKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMrkMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateDefaultClientSupplierInput;
import software.amazon.cryptography.materialproviders.model.CreateDefaultCryptographicMaterialsManagerInput;
import software.amazon.cryptography.materialproviders.model.CreateRequiredEncryptionContextCMMInput;
import software.amazon.cryptography.materialproviders.model.DiscoveryFilter;
import software.amazon.cryptography.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.model.StormTrackingCache;
import software.amazon.cryptography.primitives.model.ECDHCurveSpec;

final class Section2_4Conventions {
  private Section2_4Conventions() {}

  // 2.4: Requests in, responses out, with builders
  static String requests(KeyStore keyStore) {
    // @card 24-requests
    CreateKeyInput input = CreateKeyInput.builder()
        .branchKeyIdentifier("tenant-a-key")
        .encryptionContext(Collections.singletonMap("tenant", "TenantA"))
        .build();
    CreateKeyOutput output = keyStore.CreateKey(input);
    String branchKeyId = output.branchKeyIdentifier();
    // @end
    return branchKeyId;
  }

  // 2.4: create, defaultXxx, and of
  static Object[] factories(MaterialProviders mpl, IKeyring keyring, String kmsKeyArn) {
    // @card 24-factories
    ICryptographicMaterialsManager cmm = mpl.CreateDefaultCryptographicMaterialsManager(
        CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(keyring).build());
    IClientSupplier clientSupplier = mpl.CreateDefaultClientSupplier(CreateDefaultClientSupplierInput.builder().build());
    DiscoveryFilter filter = DiscoveryFilter.builder()
        .accountIds(Collections.singletonList("111122223333")).partition("aws").build();
    KMSConfiguration kmsConfiguration = KMSConfiguration.builder().kmsKeyArn(kmsKeyArn).build();
    byte[] wrappingKey = new byte[32];
    new SecureRandom().nextBytes(wrappingKey);
    // @end
    return new Object[] {cmm, clientSupplier, filter, kmsConfiguration, wrappingKey};
  }

  // 2.4: The old member names, with acronyms as words
  static Object[] names(ICryptographicMaterialsManager cmm, String tableName, String kmsKeyArn) {
    // @card 24-names
    KeyStoreConfig keyStoreConfig = KeyStoreConfig.builder()
        .ddbTableName(tableName)
        .kmsConfiguration(KMSConfiguration.builder().kmsKeyArn(kmsKeyArn).build())
        .build();
    StormTrackingCache cache = StormTrackingCache.builder()
        .entryCapacity(1000).gracePeriod(10).graceInterval(1).fanOut(20)
        .inFlightTTL(10).sleepMilli(20).build();
    CreateRequiredEncryptionContextCMMInput input = CreateRequiredEncryptionContextCMMInput.builder()
        .underlyingCMM(cmm).requiredEncryptionContextKeys(Arrays.asList("tenant")).build();
    ECDHCurveSpec curve = ECDHCurveSpec.ECC_NIST_P256;
    // @end
    return new Object[] {keyStoreConfig, cache, input, curve};
  }

  // 2.4: Varargs, Duration, and Optional
  static boolean varargs(MaterialProviders mpl, ICryptographicMaterialsManager cmm, KeyStore keyStore,
      String branchKeyId, EncryptionMaterials materials) {
    // @card 24-varargs
    ICryptographicMaterialsManager requiredCmm = mpl.CreateRequiredEncryptionContextCMM(
        CreateRequiredEncryptionContextCMMInput.builder()
            .underlyingCMM(cmm).requiredEncryptionContextKeys(Arrays.asList("tenant", "purpose")).build());
    IKeyring keyring = mpl.CreateAwsKmsHierarchicalKeyring(CreateAwsKmsHierarchicalKeyringInput.builder()
        .keyStore(keyStore).branchKeyId(branchKeyId).ttlSeconds(600).build());
    boolean hasDataKey = materials.plaintextDataKey() != null;
    // @end
    return requiredCmm != null && keyring != null && hasDataKey;
  }

  // 2.4: Closing is optional
  static byte[] close(MaterialProviders mpl, AwsCrypto crypto, String keyArn, byte[] plaintext,
      Map<String, String> encryptionContext) {
    // @card 24-close
    IKeyring keyring = mpl.CreateAwsKmsMrkMultiKeyring(
        CreateAwsKmsMrkMultiKeyringInput.builder().generator(keyArn).build());
    byte[] ciphertext = crypto.encryptData(keyring, plaintext, encryptionContext).getResult();
    // IKeyring has no close(): the KMS clients the keyring created are never closed.
    // @end
    return ciphertext;
  }
}
