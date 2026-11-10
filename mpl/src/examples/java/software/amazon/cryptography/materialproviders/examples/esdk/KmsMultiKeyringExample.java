// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import software.amazon.cryptography.esdk.EncryptResponse;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMultiKeyring;

/**
 * Encrypts a message under two KMS keys with a KMS multi keyring, so either key alone can decrypt it.
 *
 * <p>Arguments: the ARNs of two symmetric KMS keys, in any Regions. Calls KMS GenerateDataKey, Encrypt, and Decrypt.
 */
public final class KmsMultiKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private KmsMultiKeyringExample() {}

  public static void main(String[] args) {
    if (args.length != 2) {
      throw new IllegalArgumentException("Arguments: <generator-kms-key-arn> <additional-kms-key-arn>");
    }
    run(args[0], args[1]);
  }

  public static void run(String generatorKeyArn, String additionalKeyArn) {
    // 1. Instantiate the ESDK.
    EsdkClient esdk = EsdkClient.create();
    Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // 2. Create the multi keyring and encrypt.
    // The generator key creates the data key and the additional key encrypts it again.
    // Without a client supplier, the keyring creates a client per Region and closes them when it is closed.
    EncryptResponse encryptResponse;
    try (
      AwsKmsMultiKeyring keyring = AwsKmsMultiKeyring
        .builder()
        .generator(generatorKeyArn)
        .kmsKeyIds(additionalKeyArn)
        .build()
    ) {
      encryptResponse =
        esdk.encrypt(b -> b.plaintext(EXAMPLE_DATA).keyring(keyring).encryptionContext(encryptionContext));
      byte[] decrypted = esdk
        .decrypt(b -> b.ciphertext(encryptResponse.ciphertext()).keyring(keyring).encryptionContext(encryptionContext))
        .plaintext();
      if (!Arrays.equals(decrypted, EXAMPLE_DATA)) {
        throw new IllegalStateException("Decrypted plaintext does not match");
      }
    }

    // 3. Decrypt with only the additional key, for example from a reader that may not use the generator key.
    // A multi keyring without a generator decrypts, but cannot encrypt.
    try (AwsKmsMultiKeyring additionalKeyOnly = AwsKmsMultiKeyring.builder().kmsKeyIds(additionalKeyArn).build()) {
      byte[] decrypted = esdk
        .decrypt(b ->
          b.ciphertext(encryptResponse.ciphertext()).keyring(additionalKeyOnly).encryptionContext(encryptionContext)
        )
        .plaintext();
      if (!Arrays.equals(decrypted, EXAMPLE_DATA)) {
        throw new IllegalStateException("Decrypted plaintext does not match");
      }
    }
  }
}
