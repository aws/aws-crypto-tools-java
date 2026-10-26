// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/** Pattern (d): a local AES-256 wrapping key. ESDK example: RawAesKeyringExample. */
public final class RawAesKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private RawAesKeyringExample() {}

  public static void encryptAndDecrypt() {
    EsdkLikeClient crypto = EsdkLikeClient.builder().build();
    Keyring keyring;
    // Real code loads the key from an HSM or key management system; the keyring keeps its own copy,
    // so the caller's copy can be destroyed right away.
    try (SecretBytes aesKey = SecretBytes.random(32)) {
      keyring = RawAesKeyring
        .builder()
        .keyNamespace("my-key-namespace")
        .keyName("my-aes-key-name")
        .wrappingKey(aesKey)
        .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
        .build();
    }
    Map<String, String> encryptionContext = new HashMap<>();
    encryptionContext.put("encryption", "context");
    encryptionContext.put("is not", "secret");

    byte[] ciphertext = crypto.encryptData(keyring, EXAMPLE_DATA, encryptionContext);
    Expect.equal(EXAMPLE_DATA, crypto.decryptData(keyring, ciphertext, encryptionContext).getResult());
  }
}
