// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.dbesdk;

import java.util.LinkedHashMap;
import java.util.Map;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.examples.dbesdk.DbEsdkLikeItemEncryptor.CryptoAction;

/** The table and item the DB-ESDK examples share: partition_key and sort_key are signed, sensitive_data is encrypted. */
final class ExampleItems {

  static final String TABLE = "ExampleTable";
  static final String PARTITION_KEY = "partition_key";
  static final String SORT_KEY = "sort_key";
  static final String SENSITIVE = "sensitive_data";

  private ExampleItems() {}

  static Map<String, CryptoAction> actions() {
    Map<String, CryptoAction> actions = new LinkedHashMap<>();
    actions.put(PARTITION_KEY, CryptoAction.SIGN_ONLY);
    actions.put(SORT_KEY, CryptoAction.SIGN_ONLY);
    actions.put(SENSITIVE, CryptoAction.ENCRYPT_AND_SIGN);
    return actions;
  }

  static Map<String, String> item(String partitionKey) {
    Map<String, String> item = new LinkedHashMap<>();
    item.put(PARTITION_KEY, partitionKey);
    item.put(SORT_KEY, "0");
    item.put(SENSITIVE, "encrypt and sign me!");
    return item;
  }

  /** The example table's configuration with {@code keyring}. */
  static DbEsdkLikeItemEncryptor encryptor(Keyring keyring) {
    return DbEsdkLikeItemEncryptor
      .builder()
      .logicalTableName(TABLE)
      .partitionKeyName(PARTITION_KEY)
      .sortKeyName(SORT_KEY)
      .attributeActionsOnEncrypt(actions())
      .keyring(keyring)
      .build();
  }

  /** Encrypts {@code item}, checks that it decrypts to itself, and returns the encrypted item. */
  static Map<String, String> roundTrip(DbEsdkLikeItemEncryptor encryptor, Map<String, String> item) {
    Map<String, String> encrypted = encryptor.encryptItem(item);
    requireEqual(item, encryptor.decryptItem(encrypted));
    return encrypted;
  }

  static void requireEqual(Map<String, String> expected, Map<String, String> actual) {
    if (!expected.equals(actual)) {
      throw new IllegalStateException("Decrypted item " + actual + " differs from " + expected);
    }
  }
}
