// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples.dbesdk;

import java.util.Map;
import software.amazon.cryptography.mpl.SecretBytes;
import software.amazon.cryptography.mpl.keyrings.AesWrappingAlg;
import software.amazon.cryptography.mpl.keyrings.RawAesKeyring;

/**
 * Customer example (RawAesKeyringExample): a local AES-256 wrapping key.
 * The namespace and name are stored with every encrypted data key and must match on decrypt.
 */
public final class RawAesKeyringExample {

  private RawAesKeyringExample() {}

  /**
   * @param aesKey 32 bytes from a key management system; {@code SecretBytes.random(32)} for a test
   * @return the encrypted item
   */
  public static Map<String, String> encryptAndDecrypt(SecretBytes aesKey) {
    RawAesKeyring keyring = RawAesKeyring
      .builder()
      .keyNamespace("my-key-namespace")
      .keyName("my-aes-key-name")
      .wrappingKey(aesKey)
      .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
      .build();
    return ExampleItems.roundTrip(ExampleItems.encryptor(keyring), ExampleItems.item("rawAesKeyringItem"));
  }
}
