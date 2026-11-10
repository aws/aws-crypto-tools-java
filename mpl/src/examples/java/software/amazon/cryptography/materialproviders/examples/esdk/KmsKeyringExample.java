// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.esdk.DecryptResponse;
import software.amazon.cryptography.esdk.EncryptResponse;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsKeyring;

/**
 * Encrypts and decrypts a message with an AWS KMS keyring, which protects the data key under one KMS key.
 *
 * <p>Arguments: the ARN of a symmetric KMS key in the SDK's default Region. Calls KMS GenerateDataKey and Decrypt.
 */
public final class KmsKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private KmsKeyringExample() {}

  public static void main(String[] args) {
    if (args.length != 1) {
      throw new IllegalArgumentException("Arguments: <kms-key-arn>");
    }
    // The keyring never closes a client it was given, so the caller does.
    try (KmsClient kmsClient = KmsClient.create()) {
      run(args[0], kmsClient);
    }
  }

  public static void run(String keyArn, KmsClient kmsClient) {
    // 1. Instantiate the ESDK.
    EsdkClient esdk = EsdkClient.create();

    // 2. Create the AWS KMS keyring.
    // The client must be in the key's Region; build one keyring and reuse it, since it is thread-safe.
    Keyring keyring = AwsKmsKeyring.builder().kmsKeyId(keyArn).kmsClient(kmsClient).build();

    // 3. Encrypt and decrypt the data.
    Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");
    EncryptResponse encryptResponse = esdk.encrypt(b ->
      b.plaintext(EXAMPLE_DATA).keyring(keyring).encryptionContext(encryptionContext)
    );
    DecryptResponse decryptResponse = esdk.decrypt(b ->
      b.ciphertext(encryptResponse.ciphertext()).keyring(keyring).encryptionContext(encryptionContext)
    );
    if (!Arrays.equals(decryptResponse.plaintext(), EXAMPLE_DATA)) {
      throw new IllegalStateException("Decrypted plaintext does not match");
    }

    // 4. The default suite signs the message, so its context also holds the public verification key.
    if (!decryptResponse.encryptionContext().containsKey("aws-crypto-public-key")) {
      throw new IllegalStateException("The message has no verification key");
    }
  }
}
