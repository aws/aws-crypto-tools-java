// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import software.amazon.cryptography.materialproviders.examples.esdk.integration.CommitmentPolicy;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.ClientSupplier;

/**
 * Pattern (a), the most common setup: encrypt under a generator KMS key and a second KMS key; either decrypts.
 * ESDK examples: BasicEncryptionKeyringExample, MultipleCmkEncryptKeyringExample.
 */
public final class KmsMultiKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private KmsMultiKeyringExample() {}

  /**
   * @param clientSupplier real code leaves it out: the keyring then creates a client per Region
   *   and closes those clients when the keyring is closed
   */
  public static void encryptAndDecrypt(String generatorKeyArn, String additionalKeyArn, ClientSupplier clientSupplier) {
    EsdkLikeClient crypto = EsdkLikeClient.builder().withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt).build();
    Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    byte[] ciphertext;
    // Real AWS: AwsKmsMultiKeyring.builder().generator(generatorKeyArn).kmsKeyIds(...).build()
    try (
      AwsKmsMultiKeyring keyring = AwsKmsMultiKeyring
        .builder()
        .generator(generatorKeyArn)
        .kmsKeyIds(additionalKeyArn)
        .clientSupplier(clientSupplier)
        .build()
    ) {
      ciphertext = crypto.encryptData(keyring, EXAMPLE_DATA, encryptionContext);
      Expect.equal(EXAMPLE_DATA, crypto.decryptData(keyring, ciphertext, encryptionContext).getResult());
    }

    // The second key alone also decrypts: a multi keyring without a generator.
    try (
      AwsKmsMultiKeyring additionalKeyOnly = AwsKmsMultiKeyring
        .builder()
        .kmsKeyIds(additionalKeyArn)
        .clientSupplier(clientSupplier)
        .build()
    ) {
      Expect.equal(EXAMPLE_DATA, crypto.decryptData(additionalKeyOnly, ciphertext, encryptionContext).getResult());
    }
  }
}
