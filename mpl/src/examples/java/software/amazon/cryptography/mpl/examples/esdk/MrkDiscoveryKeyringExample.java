// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import software.amazon.cryptography.mpl.keyrings.AwsKmsMrkDiscoveryMultiKeyring;
import software.amazon.cryptography.mpl.keyrings.AwsKmsMrkMultiKeyring;
import software.amazon.cryptography.mpl.keyrings.ClientSupplier;
import software.amazon.cryptography.mpl.keyrings.DiscoveryFilter;

/**
 * Encrypt with a multi-Region key in one Region; decrypt in another Region with a multi-Region-aware discovery keyring.
 * ESDK example: DiscoveryMultiRegionDecryptionKeyringExample (which encrypts with a master key provider instead).
 */
public final class MrkDiscoveryKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private MrkDiscoveryKeyringExample() {}

  /** @param clientSupplier real code leaves it out of both keyrings */
  public static void encryptAndDecrypt(
    String mrkArn,
    String decryptRegion,
    String partition,
    String accountId,
    ClientSupplier clientSupplier
  ) {
    EsdkLikeClient crypto = EsdkLikeClient.builder().build();
    Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    byte[] ciphertext;
    try (AwsKmsMrkMultiKeyring encrypting = AwsKmsMrkMultiKeyring.builder().generator(mrkArn).clientSupplier(clientSupplier).build()) {
      ciphertext = crypto.encryptData(encrypting, EXAMPLE_DATA, encryptionContext);
    }

    try (
      AwsKmsMrkDiscoveryMultiKeyring decrypting = AwsKmsMrkDiscoveryMultiKeyring
        .builder()
        .regions(Collections.singletonList(decryptRegion))
        .discoveryFilter(DiscoveryFilter.of(Collections.singletonList(accountId), partition))
        .clientSupplier(clientSupplier)
        .build()
    ) {
      Expect.equal(EXAMPLE_DATA, crypto.decryptData(decrypting, ciphertext, encryptionContext).getResult());
    }
  }
}
