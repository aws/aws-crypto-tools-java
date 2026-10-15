// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples.dbesdk;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import software.amazon.cryptography.mpl.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.mpl.keyrings.AwsKmsMrkDiscoveryMultiKeyring;
import software.amazon.cryptography.mpl.keyrings.ClientSupplier;
import software.amazon.cryptography.mpl.keyrings.DiscoveryFilter;

/**
 * Customer example (MrkDiscoveryMultiKeyringExample): a reader that does not know which key encrypted an item
 * decrypts with whatever multi-Region key the item names, through its own Region,
 * as long as the key is in an allowed account.
 */
public final class MrkDiscoveryMultiKeyringExample {

  private MrkDiscoveryMultiKeyringExample() {}

  /**
   * Decrypts {@code encryptedItem} in {@code readerRegion}.
   *
   * @param clientSupplier the KMS client per Region; with real AWS, leave it out
   * @return the decrypted item
   */
  public static Map<String, String> decrypt(
    Map<String, String> encryptedItem,
    String readerRegion,
    List<String> allowedAccountIds,
    ClientSupplier clientSupplier
  ) {
    // With real AWS: AwsKmsMrkDiscoveryMultiKeyring.builder().regions(...).discoveryFilter(...).build()
    try (
      AwsKmsMrkDiscoveryMultiKeyring keyring = AwsKmsMrkDiscoveryMultiKeyring
        .builder()
        .regions(Collections.singletonList(readerRegion))
        .discoveryFilter(DiscoveryFilter.of(allowedAccountIds, "aws"))
        .clientSupplier(clientSupplier)
        .build()
    ) {
      return ExampleItems.encryptor(keyring).decryptItem(encryptedItem);
    }
  }

  /**
   * Error handling: when no keyring can decrypt any data key, for example because the filter excludes the key's
   * account, the failure lists why each attempt failed. Dafny-based DB-ESDK customers read this list from
   * {@code CollectionOfErrors.list()}.
   *
   * @return each attempt's failure, in order
   */
  public static List<Throwable> whyDecryptFailed(
    Map<String, String> encryptedItem,
    String readerRegion,
    List<String> allowedAccountIds,
    ClientSupplier clientSupplier
  ) {
    try {
      decrypt(encryptedItem, readerRegion, allowedAccountIds, clientSupplier);
    } catch (NoMatchingDataKeyException e) {
      return e.failures();
    }
    throw new IllegalStateException("Decrypt succeeded");
  }
}
