// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.dbesdk;

import java.util.Map;
import software.amazon.cryptography.materialproviders.DbeAlgorithmSuite;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.ClientSupplier;

/**
 * Customer example, the DB-ESDK default: an AWS KMS multi-Region-key-aware multi keyring as the table's keyring
 * (BasicPutGetExample, MultiMrkKeyringExample).
 * The item is encrypted under a multi-Region key in one Region and decrypted under its replica in another.
 */
public final class MrkMultiKeyringExample {

  private MrkMultiKeyringExample() {}

  /**
   * @param mrkArn the multi-Region key in the Region that encrypts
   * @param replicaArn the same key's replica in the Region that decrypts
   * @param clientSupplier the KMS client per Region; with real AWS, leave it out (see below)
   * @return the encrypted item
   */
  public static Map<String, String> encryptAndDecryptInAnotherRegion(String mrkArn, String replicaArn, ClientSupplier clientSupplier) {
    // With real AWS: AwsKmsMrkMultiKeyring.builder().generator(mrkArn).build()
    // The keyring then makes and owns one default KMS client per Region; close it to close them.
    AwsKmsMrkMultiKeyring writerKeyring = AwsKmsMrkMultiKeyring.builder().generator(mrkArn).clientSupplier(clientSupplier).build();
    AwsKmsMrkMultiKeyring readerKeyring = AwsKmsMrkMultiKeyring.builder().generator(replicaArn).clientSupplier(clientSupplier).build();
    DbEsdkLikeItemEncryptor writer = DbEsdkLikeItemEncryptor
      .builder()
      .logicalTableName(ExampleItems.TABLE)
      .partitionKeyName(ExampleItems.PARTITION_KEY)
      .sortKeyName(ExampleItems.SORT_KEY)
      .attributeActionsOnEncrypt(ExampleItems.actions())
      .keyring(writerKeyring)
      .algorithmSuite(DbeAlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384)
      .build();
    Map<String, String> item = ExampleItems.item("mrkMultiKeyringItem");
    Map<String, String> encrypted = writer.encryptItem(item);

    ExampleItems.requireEqual(item, ExampleItems.encryptor(readerKeyring).decryptItem(encrypted));
    return encrypted;
  }
}
