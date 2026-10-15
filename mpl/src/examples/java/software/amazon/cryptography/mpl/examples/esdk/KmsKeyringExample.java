// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.keyrings.AwsKmsKeyring;

/**
 * One KMS key and a client the customer configures (ESDK examples: CustomizeSDKClient's decrypt half,
 * RequiredEncryptionContextCMMExample's keyring). The keyring never closes the client.
 */
public final class KmsKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private KmsKeyringExample() {}

  /** @param kmsClient real AWS: {@code KmsClient.builder().region(...).httpClient(...).build()} */
  public static void encryptAndDecrypt(String keyArn, KmsClient kmsClient) {
    EsdkLikeClient crypto = EsdkLikeClient.builder().build();
    Keyring keyring = AwsKmsKeyring.builder().kmsKeyId(keyArn).kmsClient(kmsClient).build();
    Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    byte[] ciphertext = crypto.encryptData(keyring, EXAMPLE_DATA, encryptionContext);
    EsdkLikeClient.Decrypted decrypted = crypto.decryptData(keyring, ciphertext, encryptionContext);

    Expect.equal(EXAMPLE_DATA, decrypted.getResult());
    // The default suite signs, so the context also holds the public verification key.
    Expect.isTrue(decrypted.getEncryptionContext().containsKey("aws-crypto-public-key"), "a verification key in the context");
  }
}
