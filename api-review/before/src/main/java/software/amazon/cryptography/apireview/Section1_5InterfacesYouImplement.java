// Section 1.5 of the API review doc: Interfaces you implement
// Before: the Dafny-based MPL 1.11.1, with ESDK 3.0.2 and DB-ESDK 3.3.0.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.materialproviders.IBranchKeyIdSupplier;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsCache;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsHierarchicalKeyringInput;
import software.amazon.cryptography.materialproviders.model.DecryptMaterialsInput;
import software.amazon.cryptography.materialproviders.model.DecryptMaterialsOutput;
import software.amazon.cryptography.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.model.DeleteCacheEntryInput;
import software.amazon.cryptography.materialproviders.model.ESDKAlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.model.EntryDoesNotExist;
import software.amazon.cryptography.materialproviders.model.GetBranchKeyIdInput;
import software.amazon.cryptography.materialproviders.model.GetBranchKeyIdOutput;
import software.amazon.cryptography.materialproviders.model.GetCacheEntryInput;
import software.amazon.cryptography.materialproviders.model.GetCacheEntryOutput;
import software.amazon.cryptography.materialproviders.model.GetEncryptionMaterialsInput;
import software.amazon.cryptography.materialproviders.model.GetEncryptionMaterialsOutput;
import software.amazon.cryptography.materialproviders.model.OnDecryptInput;
import software.amazon.cryptography.materialproviders.model.OnDecryptOutput;
import software.amazon.cryptography.materialproviders.model.OnEncryptInput;
import software.amazon.cryptography.materialproviders.model.OnEncryptOutput;
import software.amazon.cryptography.materialproviders.model.PutCacheEntryInput;
import software.amazon.cryptography.materialproviders.model.UpdateUsageMetadataInput;

final class Section1_5InterfacesYouImplement {
  private Section1_5InterfacesYouImplement() {}

  // 1.5: Keyrings take requests and return responses
  static final class LocalKeyring implements IKeyring {
    // @card 14-keyring
    @Override
    public OnEncryptOutput OnEncrypt(OnEncryptInput input) {
      EncryptionMaterials materials = input.materials();
      EncryptionMaterials wrapped = addEncryptedDataKey(materials);
      return OnEncryptOutput.builder().materials(wrapped).build();
    }

    @Override
    public OnDecryptOutput OnDecrypt(OnDecryptInput input) {
      DecryptionMaterials materials = input.materials();
      DecryptionMaterials unwrapped = decryptOneOf(materials, input.encryptedDataKeys());
      return OnDecryptOutput.builder().materials(unwrapped).build();
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
  static EncryptionMaterials immutable(EncryptionMaterials materials, byte[] dataKey, EncryptedDataKey edk) {
    // @card 14-immutable
    EncryptionMaterials withKey = materials.toBuilder()
        .plaintextDataKey(ByteBuffer.wrap(dataKey))
        .build();
    List<EncryptedDataKey> edks = new ArrayList<>(withKey.encryptedDataKeys());
    edks.add(edk);
    EncryptionMaterials result = withKey.toBuilder().encryptedDataKeys(edks).build();
    // @end
    return result;
  }

  // 1.5: CMMs take requests, with the suite as algorithmSuite()
  static final class DefaultSuiteCmm implements ICryptographicMaterialsManager {
    private static final AlgorithmSuiteId DEFAULT_SUITE = AlgorithmSuiteId.builder()
        .ESDK(ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384).build();
    private final ICryptographicMaterialsManager underlying;

    DefaultSuiteCmm(ICryptographicMaterialsManager underlying) {
      this.underlying = underlying;
    }

    // @card 14-cmm
    @Override
    public GetEncryptionMaterialsOutput GetEncryptionMaterials(GetEncryptionMaterialsInput input) {
      AlgorithmSuiteId suite = input.algorithmSuiteId();
      if (suite == null) {
        input = input.toBuilder().algorithmSuiteId(DEFAULT_SUITE).build();
      }
      return underlying.GetEncryptionMaterials(input);
    }
    // @end

    @Override
    public DecryptMaterialsOutput DecryptMaterials(DecryptMaterialsInput input) {
      return underlying.DecryptMaterials(input);
    }
  }

  // 1.5: A cache miss is an empty entry
  static final class MapCache implements ICryptographicMaterialsCache {
    private final Map<ByteBuffer, GetCacheEntryOutput> entries = new java.util.concurrent.ConcurrentHashMap<>();

    // @card 14-cache
    @Override
    public GetCacheEntryOutput GetCacheEntry(GetCacheEntryInput input) {
      GetCacheEntryOutput entry = entries.get(input.identifier());
      if (entry == null) {
        throw EntryDoesNotExist.builder().message("No cache entry").build();
      }
      return entry;
    }
    // @end

    @Override
    public void PutCacheEntry(PutCacheEntryInput input) {
      entries.put(input.identifier(), GetCacheEntryOutput.builder()
          .materials(input.materials()).creationTime(input.creationTime()).expiryTime(input.expiryTime())
          .messagesUsed(input.messagesUsed()).bytesUsed(input.bytesUsed()).build());
    }

    @Override
    public void DeleteCacheEntry(DeleteCacheEntryInput input) {
      entries.remove(input.identifier());
    }

    @Override
    public void UpdateUsageMetadata(UpdateUsageMetadataInput input) {}
  }

  // 1.5: One-method suppliers take lambdas
  static IKeyring tenantKeyring(MaterialProviders mpl, KeyStore keyStore, Map<String, String> branchKeyIds) {
    // @card 14-supplier
    IBranchKeyIdSupplier supplier = new IBranchKeyIdSupplier() {
      @Override
      public GetBranchKeyIdOutput GetBranchKeyId(GetBranchKeyIdInput input) {
        String tenant = input.encryptionContext().get("tenant");
        return GetBranchKeyIdOutput.builder().branchKeyId(branchKeyIds.get(tenant)).build();
      }
    };
    IKeyring keyring = mpl.CreateAwsKmsHierarchicalKeyring(CreateAwsKmsHierarchicalKeyringInput.builder()
        .keyStore(keyStore).branchKeyIdSupplier(supplier).ttlSeconds(600).build());
    // @end
    return keyring;
  }
}
