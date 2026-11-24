// Section 1.5 of the API review doc: Interfaces you implement
// After: the native MPL 2.0.0, with the ESDK 4.0 sketch and the DB-ESDK stand-ins (proposals).
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.DecryptMaterialsRequest;
import software.amazon.cryptography.materialproviders.DecryptMaterialsResponse;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsRequest;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsResponse;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnDecryptResponse;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.cache.CacheEntry;
import software.amazon.cryptography.materialproviders.cache.CacheKey;
import software.amazon.cryptography.materialproviders.cache.CryptographicMaterialsCache;
import software.amazon.cryptography.materialproviders.cache.DeleteCacheEntryRequest;
import software.amazon.cryptography.materialproviders.cache.DeleteCacheEntryResponse;
import software.amazon.cryptography.materialproviders.cache.GetCacheEntryRequest;
import software.amazon.cryptography.materialproviders.cache.GetCacheEntryResponse;
import software.amazon.cryptography.materialproviders.cache.PutCacheEntryRequest;
import software.amazon.cryptography.materialproviders.cache.PutCacheEntryResponse;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;
import software.amazon.cryptography.materialproviders.keyrings.BranchKeyIdSupplier;
import software.amazon.cryptography.materialproviders.keyrings.GetBranchKeyIdResponse;
import software.amazon.cryptography.materialproviders.keystore.DynamoDbKeyStore;

final class Section1_5InterfacesYouImplement {
  private Section1_5InterfacesYouImplement() {}

  // 1.5: Keyrings take requests and return responses
  static final class LocalKeyring implements Keyring {
    // @card 14-keyring
    @Override
    public OnEncryptResponse onEncrypt(OnEncryptRequest request) {
      EncryptionMaterials materials = request.materials();
      EncryptionMaterials wrapped = addEncryptedDataKey(materials);
      return OnEncryptResponse.builder().materials(wrapped).build();
    }

    @Override
    public OnDecryptResponse onDecrypt(OnDecryptRequest request) {
      DecryptionMaterials materials = request.materials();
      DecryptionMaterials unwrapped = decryptOneOf(materials, request.encryptedDataKeys());
      return OnDecryptResponse.builder().materials(unwrapped).build();
    }
    // @end 14-keyring

    private static EncryptionMaterials addEncryptedDataKey(EncryptionMaterials materials) {
      return materials;
    }

    private static DecryptionMaterials decryptOneOf(DecryptionMaterials materials, List<EncryptedDataKey> edks) {
      return materials;
    }
  }

  // 1.5: Materials are immutable
  static EncryptionMaterials immutable(EncryptionMaterials materials, SecretBytes dataKey, EncryptedDataKey edk) {
    // @card 14-immutable
    EncryptionMaterials withKey = materials.withPlaintextDataKey(dataKey);
    EncryptionMaterials result = withKey.withEncryptedDataKey(edk);
    // Each with* call copies the key, so the in-between materials can be destroyed.
    withKey.destroy();
    // @end
    return result;
  }

  // 1.5: CMMs take requests, with the suite as algorithmSuite()
  static final class DefaultSuiteCmm implements CryptographicMaterialsManager {
    private static final AlgorithmSuite DEFAULT_SUITE = EsdkAlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384;
    private final CryptographicMaterialsManager underlying;

    DefaultSuiteCmm(CryptographicMaterialsManager underlying) {
      this.underlying = underlying;
    }

    // @card 14-cmm
    @Override
    public GetEncryptionMaterialsResponse getEncryptionMaterials(GetEncryptionMaterialsRequest request) {
      Optional<AlgorithmSuite> suite = request.algorithmSuite();
      if (!suite.isPresent()) {
        request = request.toBuilder().algorithmSuite(DEFAULT_SUITE).build();
      }
      return underlying.getEncryptionMaterials(request);
    }
    // @end

    @Override
    public DecryptMaterialsResponse decryptMaterials(DecryptMaterialsRequest request) {
      return underlying.decryptMaterials(request);
    }
  }

  // 1.5: A cache miss is an empty entry
  static final class MapCache implements CryptographicMaterialsCache {
    private final Map<CacheKey, CacheEntry> entries = new ConcurrentHashMap<>();

    // @card 14-cache
    @Override
    public GetCacheEntryResponse getCacheEntry(GetCacheEntryRequest request) {
      CacheEntry entry = entries.get(request.key());
      // A miss is a response without an entry.
      return entry == null
          ? GetCacheEntryResponse.builder().build()
          : GetCacheEntryResponse.builder().entry(entry).build();
    }
    // @end

    @Override
    public PutCacheEntryResponse putCacheEntry(PutCacheEntryRequest request) {
      entries.put(request.key(), request.entry());
      return PutCacheEntryResponse.builder().build();
    }

    @Override
    public DeleteCacheEntryResponse deleteCacheEntry(DeleteCacheEntryRequest request) {
      entries.remove(request.key());
      return DeleteCacheEntryResponse.builder().build();
    }
  }

  // 1.5: One-method suppliers take lambdas
  static Keyring tenantKeyring(DynamoDbKeyStore keyStore, Map<String, String> branchKeyIds) {
    // @card 14-supplier
    BranchKeyIdSupplier supplier = request -> {
      String tenant = request.encryptionContext().get("tenant");
      return GetBranchKeyIdResponse.builder().branchKeyId(branchKeyIds.get(tenant)).build();
    };
    AwsKmsHierarchicalKeyring keyring = AwsKmsHierarchicalKeyring.builder()
        .keyStore(keyStore).branchKeyIdSupplier(supplier).ttl(Duration.ofMinutes(10)).build();
    // @end
    return keyring;
  }
}
