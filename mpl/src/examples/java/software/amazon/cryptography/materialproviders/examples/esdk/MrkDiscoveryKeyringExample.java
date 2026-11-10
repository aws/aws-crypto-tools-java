// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkDiscoveryMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.DiscoveryFilter;

/**
 * Encrypts with a multi-Region KMS key in one Region, and decrypts in another Region with an MRK discovery keyring,
 * which calls the key's replica there.
 *
 * <p>Arguments: the ARN of a multi-Region KMS key, and a Region that has a replica of it.
 * Calls KMS GenerateDataKey and Decrypt.
 */
public final class MrkDiscoveryKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private MrkDiscoveryKeyringExample() {}

  public static void main(String[] args) {
    if (args.length != 2) {
      throw new IllegalArgumentException("Arguments: <multi-region-kms-key-arn> <replica-region>");
    }
    run(args[0], args[1]);
  }

  public static void run(String mrkArn, String replicaRegion) {
    // 1. Instantiate the ESDK.
    EsdkClient esdk = EsdkClient.create();
    Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // 2. Encrypt in the key's own Region.
    // The keyrings create their clients, one per Region, and close them when they are closed.
    byte[] ciphertext;
    try (AwsKmsMrkMultiKeyring encryptingKeyring = AwsKmsMrkMultiKeyring.builder().generator(mrkArn).build()) {
      ciphertext =
        esdk
          .encrypt(b -> b.plaintext(EXAMPLE_DATA).keyring(encryptingKeyring).encryptionContext(encryptionContext))
          .ciphertext();
    }

    // 3. Decrypt in the replica's Region.
    // The message names the key in its first Region; the keyring calls the replica with the same key id.
    String[] arn = mrkArn.split(":");
    DiscoveryFilter filter = DiscoveryFilter.of(Collections.singletonList(arn[4]), arn[1]);
    try (
      AwsKmsMrkDiscoveryMultiKeyring decryptingKeyring = AwsKmsMrkDiscoveryMultiKeyring
        .builder()
        .regions(replicaRegion)
        .discoveryFilter(filter)
        .build()
    ) {
      byte[] decrypted = esdk
        .decrypt(b -> b.ciphertext(ciphertext).keyring(decryptingKeyring).encryptionContext(encryptionContext))
        .plaintext();
      if (!Arrays.equals(decrypted, EXAMPLE_DATA)) {
        throw new IllegalStateException("Decrypted plaintext does not match");
      }
    }
  }
}
