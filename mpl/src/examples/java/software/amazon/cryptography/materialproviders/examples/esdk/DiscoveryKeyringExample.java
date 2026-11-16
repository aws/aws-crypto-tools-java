// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.esdk.EsdkNoMatchingDataKeyException;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsDiscoveryKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsDiscoveryMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsKeyring;
import software.amazon.cryptography.materialproviders.keyrings.DiscoveryFilter;

/**
 * Decrypts with discovery keyrings, which use whichever KMS key the message names, as long as a discovery filter
 * allows its account and partition.
 *
 * <p>Arguments: the ARN of a symmetric KMS key in the SDK's default Region. Calls KMS GenerateDataKey and Decrypt.
 */
public final class DiscoveryKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private DiscoveryKeyringExample() {}

  public static void main(String[] args) {
    if (args.length != 1) {
      throw new IllegalArgumentException("Arguments: <kms-key-arn>");
    }
    try (KmsClient kmsClient = KmsClient.create()) {
      run(args[0], kmsClient);
    }
  }

  public static void run(String keyArn, KmsClient kmsClient) {
    // 1. Instantiate the ESDK, and encrypt with an AWS KMS keyring.
    EsdkClient esdk = EsdkClient.create();
    Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");
    Keyring encryptingKeyring = AwsKmsKeyring.builder().kmsKeyId(keyArn).kmsClient(kmsClient).build();
    byte[] ciphertext = esdk
      .encrypt(b -> b.plaintext(EXAMPLE_DATA).keyring(encryptingKeyring).encryptionContext(encryptionContext))
      .ciphertext();

    // 2. Create a discovery filter: the accounts and partition whose keys the keyring may use.
    // Without a filter, a discovery keyring calls KMS for any key a message names, in any account.
    String[] arn = keyArn.split(":");
    String partition = arn[1];
    String region = arn[3];
    String accountId = arn[4];
    DiscoveryFilter filter = DiscoveryFilter.of(Collections.singletonList(accountId), partition);

    // 3. Decrypt with a discovery keyring: one Region, one client.
    Keyring discoveryKeyring = AwsKmsDiscoveryKeyring.builder().kmsClient(kmsClient).discoveryFilter(filter).build();
    byte[] decrypted = esdk
      .decrypt(b -> b.ciphertext(ciphertext).keyring(discoveryKeyring).encryptionContext(encryptionContext))
      .plaintext();
    if (!Arrays.equals(decrypted, EXAMPLE_DATA)) {
      throw new IllegalStateException("Decrypted plaintext does not match");
    }

    // 4. Decrypt with a discovery multi keyring: one discovery keyring per listed Region.
    // It creates a client per Region and closes them when it is closed.
    try (
      AwsKmsDiscoveryMultiKeyring multiRegionKeyring = AwsKmsDiscoveryMultiKeyring
        .builder()
        .regions(region)
        .discoveryFilter(filter)
        .build()
    ) {
      byte[] decryptedAgain = esdk
        .decrypt(b -> b.ciphertext(ciphertext).keyring(multiRegionKeyring).encryptionContext(encryptionContext))
        .plaintext();
      if (!Arrays.equals(decryptedAgain, EXAMPLE_DATA)) {
        throw new IllegalStateException("Decrypted plaintext does not match");
      }
    }

    // 5. A filter for another account skips the message's key without calling KMS.
    Keyring otherAccountKeyring = AwsKmsDiscoveryKeyring
      .builder()
      .kmsClient(kmsClient)
      .discoveryFilter(DiscoveryFilter.of(Collections.singletonList("444455556666"), partition))
      .build();
    try {
      esdk.decrypt(b -> b.ciphertext(ciphertext).keyring(otherAccountKeyring).encryptionContext(encryptionContext));
      throw new IllegalStateException("A keyring for another account decrypted the message");
    } catch (EsdkNoMatchingDataKeyException expected) {
      // No key was tried, so there are no failed attempts.
      if (!expected.failures().isEmpty()) {
        throw new IllegalStateException("A skipped key was reported as a failed attempt");
      }
    }
  }
}
