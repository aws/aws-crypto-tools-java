// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.esdk.DecryptResponse;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.esdk.EsdkNoMatchingDataKeyException;
import software.amazon.cryptography.esdk.EsdkValidationException;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.cmm.DefaultCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.cmm.RequiredEncryptionContextCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsKeyring;

/**
 * Uses the required encryption context materials manager: the required pairs are authenticated but not stored in the
 * message, so every decrypt must supply them again.
 *
 * <p>Arguments: the ARN of a symmetric KMS key in the SDK's default Region. Calls KMS GenerateDataKey and Decrypt.
 */
public final class RequiredEncryptionContextCmmExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private RequiredEncryptionContextCmmExample() {}

  public static void main(String[] args) {
    if (args.length != 1) {
      throw new IllegalArgumentException("Arguments: <kms-key-arn>");
    }
    try (KmsClient kmsClient = KmsClient.create()) {
      run(args[0], kmsClient);
    }
  }

  public static void run(String keyArn, KmsClient kmsClient) {
    // 1. Instantiate the ESDK, and create the materials managers.
    EsdkClient esdk = EsdkClient.create();
    Keyring keyring = AwsKmsKeyring.builder().kmsKeyId(keyArn).kmsClient(kmsClient).build();
    CryptographicMaterialsManager defaultCmm = DefaultCryptographicMaterialsManager.create(keyring);
    CryptographicMaterialsManager requiredContextCmm = RequiredEncryptionContextCryptographicMaterialsManager
      .builder()
      .underlyingCmm(defaultCmm)
      .requiredEncryptionContextKeys("requiredKey1", "requiredKey2")
      .build();

    // 2. Encrypt. The two required pairs are left out of the stored context.
    Map<String, String> encryptionContext = new HashMap<>();
    encryptionContext.put("key1", "value1");
    encryptionContext.put("requiredKey1", "requiredValue1");
    encryptionContext.put("requiredKey2", "requiredValue2");
    byte[] ciphertext = esdk
      .encrypt(b -> b.plaintext(EXAMPLE_DATA).materialsManager(requiredContextCmm).encryptionContext(encryptionContext))
      .ciphertext();

    // 3. Decrypt, supplying the required pairs again.
    Map<String, String> reproducedContext = new HashMap<>();
    reproducedContext.put("requiredKey1", "requiredValue1");
    reproducedContext.put("requiredKey2", "requiredValue2");
    DecryptResponse decryptResponse = esdk.decrypt(b ->
      b.ciphertext(ciphertext).materialsManager(requiredContextCmm).encryptionContext(reproducedContext)
    );
    if (!Arrays.equals(decryptResponse.plaintext(), EXAMPLE_DATA)) {
      throw new IllegalStateException("Decrypted plaintext does not match");
    }
    if (!"requiredValue1".equals(decryptResponse.encryptionContext().get("requiredKey1"))) {
      throw new IllegalStateException("The decrypted context has no required pair");
    }

    // 4. A reader with the default materials manager decrypts too, given the required pairs.
    byte[] decrypted = esdk
      .decrypt(b -> b.ciphertext(ciphertext).materialsManager(defaultCmm).encryptionContext(reproducedContext))
      .plaintext();
    if (!Arrays.equals(decrypted, EXAMPLE_DATA)) {
      throw new IllegalStateException("Decrypted plaintext does not match");
    }

    // 5. Leaving out a required pair fails.
    // The required context manager checks first; with the default one, KMS refuses to decrypt the data key.
    reproducedContext.remove("requiredKey2");
    try {
      esdk.decrypt(b ->
        b.ciphertext(ciphertext).materialsManager(requiredContextCmm).encryptionContext(reproducedContext)
      );
      throw new IllegalStateException("Decrypted without a required pair");
    } catch (EsdkValidationException expected) {
      // The reproduced context is missing requiredKey2.
    }
    try {
      esdk.decrypt(b -> b.ciphertext(ciphertext).materialsManager(defaultCmm).encryptionContext(reproducedContext));
      throw new IllegalStateException("Decrypted without a required pair");
    } catch (EsdkNoMatchingDataKeyException expected) {
      // KMS Decrypt failed for the only encrypted data key.
      if (expected.failures().isEmpty()) {
        throw new IllegalStateException("No KMS Decrypt was attempted");
      }
    }
  }
}
