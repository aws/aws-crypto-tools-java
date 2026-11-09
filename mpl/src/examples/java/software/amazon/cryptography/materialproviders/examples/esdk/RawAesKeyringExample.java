// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import software.amazon.cryptography.esdk.DecryptResponse;
import software.amazon.cryptography.esdk.EncryptResponse;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * Encrypts and decrypts a message with a raw AES keyring: data keys are wrapped under an AES-256 key the
 * application holds.
 *
 * <p>No arguments; runs without AWS.
 */
public final class RawAesKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private RawAesKeyringExample() {}

  public static void main(String[] args) {
    run();
  }

  public static void run() {
    // 1. Instantiate the ESDK.
    EsdkClient esdk = EsdkClient.create();

    // 2. Create the raw AES keyring.
    // A real application loads the key from an HSM or key management system.
    // The keyring keeps its own copy, so the caller's copy is destroyed as soon as the keyring is built.
    Keyring keyring;
    try (SecretBytes aesKey = SecretBytes.random(32)) {
      keyring =
        RawAesKeyring
          .builder()
          .keyNamespace("my-key-namespace")
          .keyName("my-aes-key-name")
          .wrappingKey(aesKey)
          .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
          .build();
    }

    // 3. Create an encryption context: authenticated with the message, but not encrypted, so it holds no secrets.
    Map<String, String> encryptionContext = new HashMap<>();
    encryptionContext.put("encryption", "context");
    encryptionContext.put("is not", "secret");

    // 4. Encrypt and decrypt the data.
    // Passing the encryption context to decrypt makes it fail unless the message has every pair.
    EncryptResponse encryptResponse = esdk.encrypt(b ->
      b.plaintext(EXAMPLE_DATA).keyring(keyring).encryptionContext(encryptionContext)
    );
    DecryptResponse decryptResponse = esdk.decrypt(b ->
      b.ciphertext(encryptResponse.ciphertext()).keyring(keyring).encryptionContext(encryptionContext)
    );
    if (!Arrays.equals(decryptResponse.plaintext(), EXAMPLE_DATA)) {
      throw new IllegalStateException("Decrypted plaintext does not match");
    }
  }
}
