// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.dbesdk;

import java.util.HashMap;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * Puts and gets an item with a raw AES keyring: data keys are wrapped under an AES-256 key the application holds,
 * so the only AWS calls are DynamoDB's.
 *
 * <p>Arguments: a table whose partition key is {@code partition_key} (string) and sort key is {@code sort_key}
 * (number). Calls DynamoDB PutItem and GetItem.
 */
public final class RawAesKeyringExample {

  private RawAesKeyringExample() {}

  public static void main(String[] args) {
    if (args.length != 1) {
      throw new IllegalArgumentException("Arguments: <table-name>");
    }
    run(args[0]);
  }

  public static void run(String tableName) {
    // 1. Create the raw AES keyring.
    // A real application loads the key from an HSM or key management system; the keyring keeps its own copy,
    // so the caller's copy is destroyed as soon as the keyring is built.
    Keyring keyring;
    try (SecretBytes aesKey = SecretBytes.random(32)) {
      keyring =
        RawAesKeyring
          .builder()
          .keyNamespace("my-key-namespace")
          .keyName("my-aes-key-name")
          .wrappingKey(aesKey)
          .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
          .build();
    }

    // 2. Configure the table, and a DynamoDB client that encrypts and decrypts its items.
    ItemEncryptionSchema schema = ItemEncryptionSchema
      .builder()
      .partitionKeyName("partition_key")
      .sortKeyName("sort_key")
      .encryptAndSign("sensitive_data")
      .signOnly("public_data")
      .build();
    DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .logicalTableName(tableName)
      .schema(schema)
      .keyring(keyring)
      .build();
    DynamoDbEncryptionInterceptor interceptor = DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();

    try (
      DynamoDbClient ddbClient = DynamoDbClient
        .builder()
        .overrideConfiguration(o -> o.addExecutionInterceptor(interceptor))
        .build()
    ) {
      // 3. Put the item, and get it back.
      Map<String, AttributeValue> item = key();
      item.put("sensitive_data", AttributeValue.builder().s("encrypt and sign me!").build());
      item.put("public_data", AttributeValue.builder().s("sign me!").build());
      ddbClient.putItem(b -> b.tableName(tableName).item(item));
      Map<String, AttributeValue> returned = ddbClient
        .getItem(b -> b.tableName(tableName).key(key()).consistentRead(true))
        .item();
      if (
        !"encrypt and sign me!".equals(returned.get("sensitive_data").s()) ||
        !"sign me!".equals(returned.get("public_data").s())
      ) {
        throw new IllegalStateException("The item did not decrypt to what was put");
      }
    }
  }

  private static Map<String, AttributeValue> key() {
    Map<String, AttributeValue> key = new HashMap<>();
    key.put("partition_key", AttributeValue.builder().s("RawAesKeyringExample").build());
    key.put("sort_key", AttributeValue.builder().n("0").build());
    return key;
  }
}
