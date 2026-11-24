// Section 2.3 of the API review doc: Value types and secrets
// After: the native MPL 2.0.0, with the ESDK 4.0 sketch and the DB-ESDK stand-ins (proposals).
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;
import javax.crypto.SecretKey;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

final class Section2_3ValueTypesAndSecrets {
  private Section2_3ValueTypesAndSecrets() {}

  // 2.3: The encryption context is its own type
  static byte[] encryptionContext() {
    // @card 23-ec
    EncryptionContext encryptionContext = EncryptionContext.of("purpose", "example", "tenant", "TenantA");
    EncryptionContext withVersion = encryptionContext.with("version", "2");
    // The AAD bytes a custom keyring authenticates.
    byte[] aad = withVersion.canonicalBytes();
    // @end
    return aad;
  }

  // 2.3: EncryptedDataKey takes byte arrays
  static byte[] encryptedDataKey(String providerId, String keyName, byte[] wrappedKey) {
    // @card 23-edk
    EncryptedDataKey edk = EncryptedDataKey.builder()
        .keyProviderId(providerId)
        .keyProviderInfo(keyName.getBytes(StandardCharsets.UTF_8))
        .ciphertext(wrappedKey)
        .build();
    byte[] info = edk.keyProviderInfo();
    // @end
    return info;
  }

  // 2.3: SecretBytes for every secret
  static SecretKey secret(DecryptionMaterials materials) {
    // @card 23-secret
    Optional<SecretBytes> dataKey = materials.plaintextDataKey();
    if (!dataKey.isPresent()) {
      throw new IllegalStateException("No data key");
    }
    SecretKey aesKey = dataKey.get().toSecretKey("AES");
    // @end
    return aesKey;
  }

  // 2.3: Secrets as SecretBytes, or bytes copied at once
  static Keyring wrappingKey(byte[] keyBytes) {
    // @card 23-wrapping
    RawAesKeyring keyring = RawAesKeyring.builder()
        .keyNamespace("HSM_01")
        .keyName("AES_256_012")
        .wrappingKey(keyBytes)
        .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
        .build();
    // The keyring copied the key, so the caller can zero its array.
    Arrays.fill(keyBytes, (byte) 0);
    // @end
    return keyring;
  }
}
