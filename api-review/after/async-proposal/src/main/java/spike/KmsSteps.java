package spike;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.exceptions.CryptographicException;

/**
 * The I/O-free half of the KMS keyring: build the KMS request, check the KMS response, update the materials.
 *
 * <p>In the real library this is where internal/KmsDataKeys.java's logic would live, called by both
 * AwsKmsKeyring (around {@code kmsClient.generateDataKey(r)}) and AwsKmsAsyncKeyring (around
 * {@code kmsAsyncClient.generateDataKey(r).thenApply(...)}). One copy of the checks, two thin I/O shells.
 * Simplified for the spike: no MRK matching, no ARN parsing, no symmetric-signing suites.
 */
final class KmsSteps {
  static final String PROVIDER_ID = "aws-kms";

  private KmsSteps() {}

  static GenerateDataKeyRequest generateDataKey(String keyId, EncryptionMaterials m, List<String> grantTokens) {
    return GenerateDataKeyRequest.builder()
        .keyId(keyId)
        .numberOfBytes(m.algorithmSuite().dataKeyLength())
        .encryptionContext(new HashMap<>(m.encryptionContext()))
        .grantTokens(grantTokens)
        .build();
  }

  static EncryptionMaterials afterGenerate(String keyId, EncryptionMaterials m, GenerateDataKeyResponse r) {
    byte[] plaintext = r.plaintext().asByteArray();
    try {
      if (plaintext.length != m.algorithmSuite().dataKeyLength()) {
        throw new CryptographicException("Invalid response from KMS GenerateDataKey: plaintext length");
      }
      if (r.keyId() == null || !r.keyId().startsWith("arn:")) {
        throw new CryptographicException("Invalid response from KMS GenerateDataKey: key id");
      }
      EncryptedDataKey edk = edk(r.keyId(), r.ciphertextBlob().asByteArray());
      // Each with* call copies the key, so the key and the in-between materials are destroyed here.
      try (SecretBytes key = SecretBytes.copyOf(plaintext)) {
        EncryptionMaterials withKey = m.withPlaintextDataKey(key);
        try {
          return withKey.withEncryptedDataKey(edk);
        } finally {
          withKey.destroy();
        }
      }
    } finally {
      Arrays.fill(plaintext, (byte) 0);
    }
  }

  static EncryptRequest encrypt(String keyId, EncryptionMaterials m, List<String> grantTokens) {
    // The caller checked plaintextDataKey().isPresent().
    return EncryptRequest.builder()
        .keyId(keyId)
        .plaintext(SdkBytes.fromByteArray(m.plaintextDataKey().get().toByteArray()))
        .encryptionContext(new HashMap<>(m.encryptionContext()))
        .grantTokens(grantTokens)
        .build();
  }

  static EncryptionMaterials afterEncrypt(EncryptionMaterials m, EncryptResponse r) {
    if (r.keyId() == null || !r.keyId().startsWith("arn:")) {
      throw new CryptographicException("Invalid response from KMS Encrypt: key id");
    }
    return m.withEncryptedDataKey(edk(r.keyId(), r.ciphertextBlob().asByteArray()));
  }

  private static EncryptedDataKey edk(String keyArn, byte[] ciphertext) {
    return EncryptedDataKey.builder().keyProviderId(PROVIDER_ID)
        .keyProviderInfo(keyArn.getBytes(StandardCharsets.UTF_8)).ciphertext(ciphertext).build();
  }

  static boolean matches(String keyId, EncryptedDataKey edk) {
    return PROVIDER_ID.equals(edk.keyProviderId()) && keyId.equals(new String(edk.keyProviderInfo(), StandardCharsets.UTF_8));
  }

  static DecryptRequest decrypt(String keyId, DecryptionMaterials m, EncryptedDataKey edk, List<String> grantTokens) {
    return DecryptRequest.builder()
        .keyId(keyId)
        .ciphertextBlob(SdkBytes.fromByteArray(edk.ciphertext()))
        .encryptionContext(new HashMap<>(m.encryptionContext()))
        .grantTokens(grantTokens)
        .build();
  }

  static DecryptionMaterials afterDecrypt(String keyId, DecryptionMaterials m, DecryptResponse r) {
    if (!keyId.equals(r.keyId())) {
      throw new CryptographicException("KMS Decrypt returned a different key id");
    }
    byte[] plaintext = r.plaintext().asByteArray();
    try (SecretBytes key = SecretBytes.copyOf(plaintext)) {
      if (plaintext.length != m.algorithmSuite().dataKeyLength()) {
        throw new CryptographicException("Invalid response from KMS Decrypt: plaintext length");
      }
      return m.withPlaintextDataKey(key);
    } finally {
      Arrays.fill(plaintext, (byte) 0);
    }
  }
}
