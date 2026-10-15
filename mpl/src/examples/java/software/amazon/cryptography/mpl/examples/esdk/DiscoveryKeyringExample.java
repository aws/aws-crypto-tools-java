// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.mpl.keyrings.AwsKmsDiscoveryKeyring;
import software.amazon.cryptography.mpl.keyrings.AwsKmsDiscoveryMultiKeyring;
import software.amazon.cryptography.mpl.keyrings.AwsKmsKeyring;
import software.amazon.cryptography.mpl.keyrings.ClientSupplier;
import software.amazon.cryptography.mpl.keyrings.DiscoveryFilter;

/**
 * Pattern (d): decrypt without naming the key, limited to the accounts a discovery filter allows.
 * ESDK example: DiscoveryDecryptionKeyringExample.
 */
public final class DiscoveryKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private DiscoveryKeyringExample() {}

  /**
   * @param kmsClient real AWS: {@code KmsClient.create()}
   * @param clientSupplier real code leaves it out of the discovery multi keyring
   */
  public static void encryptAndDecrypt(
    String keyArn,
    String region,
    String partition,
    String accountId,
    KmsClient kmsClient,
    ClientSupplier clientSupplier
  ) {
    EsdkLikeClient crypto = EsdkLikeClient.builder().build();
    Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");
    byte[] ciphertext = crypto.encryptData(
      AwsKmsKeyring.builder().kmsKeyId(keyArn).kmsClient(kmsClient).build(),
      EXAMPLE_DATA,
      encryptionContext
    );

    DiscoveryFilter filter = DiscoveryFilter.of(Collections.singletonList(accountId), partition);
    // One Region, one client.
    Keyring discovery = AwsKmsDiscoveryKeyring.builder().kmsClient(kmsClient).discoveryFilter(filter).build();
    Expect.equal(EXAMPLE_DATA, crypto.decryptData(discovery, ciphertext, encryptionContext).getResult());

    // Several Regions, a client each from the supplier.
    try (
      AwsKmsDiscoveryMultiKeyring multiRegion = AwsKmsDiscoveryMultiKeyring
        .builder()
        .regions(Collections.singletonList(region))
        .discoveryFilter(filter)
        .clientSupplier(clientSupplier)
        .build()
    ) {
      Expect.equal(EXAMPLE_DATA, crypto.decryptData(multiRegion, ciphertext, encryptionContext).getResult());
    }

    // A filter for another account skips the key, so nothing decrypts.
    Keyring otherAccount = AwsKmsDiscoveryKeyring
      .builder()
      .kmsClient(kmsClient)
      .discoveryFilter(DiscoveryFilter.of(Collections.singletonList("000000000000"), partition))
      .build();
    Expect.failure(NoMatchingDataKeyException.class, () -> crypto.decryptData(otherAccount, ciphertext, encryptionContext));
  }
}
