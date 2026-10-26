// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.dbesdk;

import java.security.KeyPair;
import java.util.Map;
import software.amazon.cryptography.materialproviders.keyrings.PaddingScheme;
import software.amazon.cryptography.materialproviders.keyrings.RawRsaKeyring;

/**
 * Customer example (RawRsaKeyringExample): a local RSA key pair with OAEP-SHA-256.
 * A keyring with only the public key can encrypt but not decrypt.
 */
public final class RawRsaKeyringExample {

  private RawRsaKeyringExample() {}

  /**
   * @param rsaKeyPair a 2048-bit or larger key pair, for example from {@code KeyPairGenerator.getInstance("RSA")}
   * @return the item encrypted by a keyring holding only the public key
   */
  public static Map<String, String> encryptAndDecrypt(KeyPair rsaKeyPair) {
    RawRsaKeyring encryptOnly = RawRsaKeyring
      .builder()
      .keyNamespace("my-key-namespace")
      .keyName("my-rsa-key-name")
      .paddingScheme(PaddingScheme.OAEP_SHA256_MGF1)
      .publicKey(rsaKeyPair.getPublic())
      .build();
    Map<String, String> item = ExampleItems.item("rawRsaKeyringItem");
    Map<String, String> encrypted = ExampleItems.encryptor(encryptOnly).encryptItem(item);

    RawRsaKeyring decrypting = RawRsaKeyring
      .builder()
      .keyNamespace("my-key-namespace")
      .keyName("my-rsa-key-name")
      .paddingScheme(PaddingScheme.OAEP_SHA256_MGF1)
      .privateKey(rsaKeyPair.getPrivate())
      .build();
    ExampleItems.requireEqual(item, ExampleItems.encryptor(decrypting).decryptItem(encrypted));
    return encrypted;
  }
}
