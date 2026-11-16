// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import software.amazon.cryptography.esdk.DecryptResponse;
import software.amazon.cryptography.esdk.EncryptResponse;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.esdk.EsdkValidationException;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.PaddingScheme;
import software.amazon.cryptography.materialproviders.keyrings.RawRsaKeyring;

/**
 * Encrypts with a raw RSA keyring that holds only the public key, and decrypts with one that holds only the
 * private key, so the party that encrypts never needs the private key.
 *
 * <p>No arguments; runs without AWS.
 */
public final class RawRsaKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private RawRsaKeyringExample() {}

  public static void main(String[] args) throws GeneralSecurityException {
    run();
  }

  public static void run() throws GeneralSecurityException {
    // 1. Instantiate the ESDK.
    EsdkClient esdk = EsdkClient.create();

    // 2. Create an RSA key pair; a real application loads it from its key storage.
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair keyPair = generator.generateKeyPair();

    // 3. Create the two keyrings.
    // The namespace and name are written into the message, so both keyrings must use the same ones.
    Keyring encryptingKeyring = RawRsaKeyring
      .builder()
      .keyNamespace("rsa-keyring")
      .keyName("rsa-key")
      .paddingScheme(PaddingScheme.OAEP_SHA256_MGF1)
      .publicKey(keyPair.getPublic())
      .build();
    Keyring decryptingKeyring = RawRsaKeyring
      .builder()
      .keyNamespace("rsa-keyring")
      .keyName("rsa-key")
      .paddingScheme(PaddingScheme.OAEP_SHA256_MGF1)
      .privateKey(keyPair.getPrivate())
      .build();

    // 4. Encrypt with the public key, and decrypt with the private key.
    Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");
    EncryptResponse encryptResponse = esdk.encrypt(b ->
      b.plaintext(EXAMPLE_DATA).keyring(encryptingKeyring).encryptionContext(encryptionContext)
    );
    DecryptResponse decryptResponse = esdk.decrypt(b ->
      b.ciphertext(encryptResponse.ciphertext()).keyring(decryptingKeyring).encryptionContext(encryptionContext)
    );
    if (!Arrays.equals(decryptResponse.plaintext(), EXAMPLE_DATA)) {
      throw new IllegalStateException("Decrypted plaintext does not match");
    }

    // 5. Each keyring refuses the other operation.
    // A missing key half is a configuration error (EsdkValidationException), not a missing data key.
    try {
      esdk.decrypt(b -> b.ciphertext(encryptResponse.ciphertext()).keyring(encryptingKeyring));
      throw new IllegalStateException("A public-key-only keyring decrypted the message");
    } catch (EsdkValidationException expected) {
      // The keyring has no private key.
    }
    try {
      esdk.encrypt(b -> b.plaintext(EXAMPLE_DATA).keyring(decryptingKeyring));
      throw new IllegalStateException("A private-key-only keyring encrypted a message");
    } catch (EsdkValidationException expected) {
      // The keyring has no public key.
    }
  }
}
