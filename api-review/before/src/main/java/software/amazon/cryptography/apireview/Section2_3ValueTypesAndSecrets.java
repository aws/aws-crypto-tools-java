// Section 2.3 of the API review doc: Value types and secrets
// Before: the Dafny-based MPL 1.11.1, with ESDK 3.0.2 and DB-ESDK 3.3.0.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import com.amazonaws.encryptionsdk.internal.EncryptionContextSerializer;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.model.CreateRawAesKeyringInput;
import software.amazon.cryptography.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.model.EncryptedDataKey;

final class Section2_3ValueTypesAndSecrets {
  private Section2_3ValueTypesAndSecrets() {}

  // 2.3: The encryption context is its own type
  static byte[] encryptionContext() {
    // @card 23-ec
    Map<String, String> encryptionContext = new HashMap<>();
    encryptionContext.put("purpose", "example");
    encryptionContext.put("tenant", "TenantA");
    Map<String, String> withVersion = new HashMap<>(encryptionContext);
    withVersion.put("version", "2");
    // The AAD bytes come from an internal ESDK class.
    byte[] aad = EncryptionContextSerializer.serialize(withVersion);
    // @end
    return aad;
  }

  // 2.3: EncryptedDataKey takes byte arrays
  static byte[] encryptedDataKey(String providerId, String keyName, byte[] wrappedKey) {
    // @card 23-edk
    EncryptedDataKey edk = EncryptedDataKey.builder()
        .keyProviderId(providerId)
        .keyProviderInfo(ByteBuffer.wrap(keyName.getBytes(StandardCharsets.UTF_8)))
        .ciphertext(ByteBuffer.wrap(wrappedKey))
        .build();
    ByteBuffer infoBuffer = edk.keyProviderInfo().duplicate();
    byte[] info = new byte[infoBuffer.remaining()];
    infoBuffer.get(info);
    // @end
    return info;
  }

  // 2.3: SecretBytes for every secret
  static SecretKey secret(DecryptionMaterials materials) {
    // @card 23-secret
    ByteBuffer dataKey = materials.plaintextDataKey();
    if (dataKey == null) {
      throw new IllegalStateException("No data key");
    }
    byte[] key = new byte[dataKey.remaining()];
    dataKey.duplicate().get(key);
    SecretKey aesKey = new SecretKeySpec(key, "AES");
    // @end
    return aesKey;
  }

  // 2.3: Secrets as SecretBytes, or bytes copied at once
  static IKeyring wrappingKey(MaterialProviders mpl, byte[] keyBytes) {
    // @card 23-wrapping
    IKeyring keyring = mpl.CreateRawAesKeyring(CreateRawAesKeyringInput.builder()
        .keyNamespace("HSM_01")
        .keyName("AES_256_012")
        .wrappingKey(ByteBuffer.wrap(keyBytes))
        .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
        .build());
    // @end
    return keyring;
  }
}
