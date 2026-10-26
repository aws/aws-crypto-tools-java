// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.cmm.DefaultCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.cmm.RequiredEncryptionContextCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsKeyring;

/**
 * Pattern (e): context keys that are authenticated but not stored in the message, so decrypt must supply them again.
 * ESDK examples: RequiredEncryptionContextCMMExample, StreamingWithRequiredEncryptionContextCMMExample.
 */
public final class RequiredEncryptionContextCmmExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private RequiredEncryptionContextCmmExample() {}

  /** @param kmsClient real AWS: {@code KmsClient.create()} */
  public static void encryptAndDecrypt(String keyArn, KmsClient kmsClient) {
    EsdkLikeClient crypto = EsdkLikeClient.builder().build();
    CryptographicMaterialsManager cmm = RequiredEncryptionContextCryptographicMaterialsManager
      .builder()
      .underlyingCmm(DefaultCryptographicMaterialsManager.of(AwsKmsKeyring.builder().kmsKeyId(keyArn).kmsClient(kmsClient).build()))
      .requiredEncryptionContextKeys("requiredKey1", "requiredKey2")
      .build();

    Map<String, String> encryptionContext = new HashMap<>();
    encryptionContext.put("key1", "value1");
    encryptionContext.put("requiredKey1", "requiredValue1");
    encryptionContext.put("requiredKey2", "requiredValue2");
    byte[] ciphertext = crypto.encryptData(cmm, EXAMPLE_DATA, encryptionContext);

    Map<String, String> reproduced = new HashMap<>();
    reproduced.put("requiredKey1", "requiredValue1");
    reproduced.put("requiredKey2", "requiredValue2");
    EsdkLikeClient.Decrypted decrypted = crypto.decryptData(cmm, ciphertext, reproduced);
    Expect.equal(EXAMPLE_DATA, decrypted.getResult());
    Expect.isTrue("requiredValue1".equals(decrypted.getEncryptionContext().get("requiredKey1")), "the required pair in the result");

    // A reader with only the plain default manager can decrypt too, given the full context:
    // reproduced pairs the message does not store become required keys of its materials.
    CryptographicMaterialsManager plain = DefaultCryptographicMaterialsManager.of(AwsKmsKeyring.builder().kmsKeyId(keyArn).kmsClient(kmsClient).build());
    Expect.equal(EXAMPLE_DATA, crypto.decryptData(plain, ciphertext, encryptionContext).getResult());

    // Leaving out a required pair fails: with the required-context manager at once,
    // with the plain one when KMS, given an incomplete context, refuses to decrypt the data key.
    reproduced.remove("requiredKey2");
    Expect.failure(ValidationException.class, () -> crypto.decryptData(cmm, ciphertext, reproduced));
    Expect.failure(NoMatchingDataKeyException.class, () -> crypto.decryptData(plain, ciphertext, reproduced));
  }
}
