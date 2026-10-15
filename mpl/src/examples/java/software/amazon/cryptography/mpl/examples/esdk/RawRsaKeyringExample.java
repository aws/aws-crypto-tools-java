// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collections;
import java.util.Map;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.keyrings.PaddingScheme;
import software.amazon.cryptography.mpl.keyrings.RawRsaKeyring;

/**
 * Encrypt with an RSA public key only; decrypt with the private key only. ESDK example: RawRsaKeyringExample.
 */
public final class RawRsaKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private RawRsaKeyringExample() {}

  public static void encryptAndDecrypt() throws GeneralSecurityException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair keyPair = generator.generateKeyPair();
    EsdkLikeClient crypto = EsdkLikeClient.builder().build();
    Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    Keyring encrypting = RawRsaKeyring
      .builder()
      .keyNamespace("rsa-keyring")
      .keyName("rsa-key")
      .paddingScheme(PaddingScheme.OAEP_SHA256_MGF1)
      .publicKey(keyPair.getPublic())
      .build();
    byte[] ciphertext = crypto.encryptData(encrypting, EXAMPLE_DATA, encryptionContext);

    Keyring decrypting = RawRsaKeyring
      .builder()
      .keyNamespace("rsa-keyring")
      .keyName("rsa-key")
      .paddingScheme(PaddingScheme.OAEP_SHA256_MGF1)
      .privateKey(keyPair.getPrivate())
      .build();
    Expect.equal(EXAMPLE_DATA, crypto.decryptData(decrypting, ciphertext, encryptionContext).getResult());

    // Each half of the pair is a configuration error for the other operation, not a missing data key.
    Expect.failure(ValidationException.class, () -> crypto.decryptData(encrypting, ciphertext, encryptionContext));
    Expect.failure(ValidationException.class, () -> crypto.encryptData(decrypting, EXAMPLE_DATA, encryptionContext));
  }
}
