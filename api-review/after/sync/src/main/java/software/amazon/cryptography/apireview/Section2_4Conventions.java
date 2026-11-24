// Section 2.4 of the API review doc: Conventions
// After: the native MPL 2.0.0, with the ESDK 4.0 sketch and the DB-ESDK stand-ins (proposals).
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.cache.StormTrackingCache;
import software.amazon.cryptography.materialproviders.cmm.DefaultCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.cmm.RequiredEncryptionContextCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.ClientSupplier;
import software.amazon.cryptography.materialproviders.keyrings.DefaultClientSupplier;
import software.amazon.cryptography.materialproviders.keyrings.DiscoveryFilter;
import software.amazon.cryptography.materialproviders.keyrings.EcdhCurveSpec;
import software.amazon.cryptography.materialproviders.keystore.CreateKeyRequest;
import software.amazon.cryptography.materialproviders.keystore.CreateKeyResponse;
import software.amazon.cryptography.materialproviders.keystore.DynamoDbKeyStore;
import software.amazon.cryptography.materialproviders.keystore.KmsConfiguration;

final class Section2_4Conventions {
  private Section2_4Conventions() {}

  // 2.4: Requests in, responses out, with builders
  static String requests(DynamoDbKeyStore keyStore) {
    // @card 24-requests
    CreateKeyRequest request = CreateKeyRequest.builder()
        .branchKeyId("tenant-a-key")
        .encryptionContext(Collections.singletonMap("tenant", "TenantA"))
        .build();
    CreateKeyResponse response = keyStore.createKey(request);
    String branchKeyId = response.branchKeyId();
    // @end
    return branchKeyId;
  }

  // 2.4: create, defaultXxx, and of
  static Object[] factories(Keyring keyring, String kmsKeyArn) {
    // @card 24-factories
    DefaultCryptographicMaterialsManager cmm = DefaultCryptographicMaterialsManager.create(keyring);
    DefaultClientSupplier clientSupplier = ClientSupplier.defaultSupplier();
    DiscoveryFilter filter = DiscoveryFilter.of(Collections.singletonList("111122223333"), "aws");
    KmsConfiguration kmsConfiguration = KmsConfiguration.kmsKeyArn(kmsKeyArn);
    SecretBytes wrappingKey = SecretBytes.random(32);
    // @end
    return new Object[] {cmm, clientSupplier, filter, kmsConfiguration, wrappingKey};
  }

  // 2.4: The old member names, with acronyms as words
  static Object[] names(CryptographicMaterialsManager cmm, String tableName, String kmsKeyArn) {
    // @card 24-names
    DynamoDbKeyStore keyStore = DynamoDbKeyStore.builder()
        .ddbTableName(tableName)
        .kmsConfiguration(KmsConfiguration.kmsKeyArn(kmsKeyArn))
        .build();
    StormTrackingCache cache = StormTrackingCache.builder()
        .entryCapacity(1000).gracePeriod(Duration.ofSeconds(10)).graceInterval(Duration.ofSeconds(1)).fanOut(20)
        .inFlightTtl(Duration.ofSeconds(10)).sleep(Duration.ofMillis(20)).build();
    RequiredEncryptionContextCryptographicMaterialsManager requiredCmm =
        RequiredEncryptionContextCryptographicMaterialsManager.builder()
            .underlyingCmm(cmm).requiredEncryptionContextKeys("tenant").build();
    EcdhCurveSpec curve = EcdhCurveSpec.ECC_NIST_P256;
    // @end
    return new Object[] {keyStore, cache, requiredCmm, curve};
  }

  // 2.4: Varargs, Duration, and Optional
  static boolean varargs(CryptographicMaterialsManager cmm, DynamoDbKeyStore keyStore, String branchKeyId,
      EncryptionMaterials materials, String keyArn, String token1, String token2) {
    // @card 24-varargs
    RequiredEncryptionContextCryptographicMaterialsManager requiredCmm =
        RequiredEncryptionContextCryptographicMaterialsManager.builder()
            .underlyingCmm(cmm).requiredEncryptionContextKeys("tenant", "purpose").build();
    AwsKmsHierarchicalKeyring keyring = AwsKmsHierarchicalKeyring.builder()
        .keyStore(keyStore).branchKeyId(branchKeyId).ttl(Duration.ofMinutes(10)).build();
    boolean hasDataKey = materials.plaintextDataKey().isPresent();
    // Each varargs setter also takes a Collection, such as a List.
    List<String> grantTokens = Arrays.asList(token1, token2);
    AwsKmsMultiKeyring kmsKeyring = AwsKmsMultiKeyring.builder().generator(keyArn).grantTokens(grantTokens).build();
    // @end
    return requiredCmm != null && keyring != null && kmsKeyring != null && hasDataKey;
  }

  // 2.4: Closing is optional
  static byte[] close(EsdkClient esdk, String keyArn, byte[] plaintext, Map<String, String> encryptionContext) {
    // @card 24-close
    // Closing is optional, and closes only the KMS clients the keyring created.
    try (AwsKmsMrkMultiKeyring keyring = AwsKmsMrkMultiKeyring.builder().generator(keyArn).build()) {
      byte[] ciphertext = esdk.encrypt(b -> b
          .plaintext(plaintext).keyring(keyring).encryptionContext(encryptionContext)).ciphertext();
      // @hide
      return ciphertext;
      // @show
      // ...
    }
    // @end
  }
}
