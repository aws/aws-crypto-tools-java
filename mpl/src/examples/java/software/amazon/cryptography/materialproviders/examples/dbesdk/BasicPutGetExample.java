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
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkMultiKeyring;

/**
 * Puts an item into a DynamoDB table and gets it back through the DB-ESDK, which encrypts and signs the item with an
 * AWS KMS keyring on the way in, and verifies and decrypts it on the way out.
 *
 * <p>Arguments: the ARN of a KMS key, single- or multi-Region, and a table whose partition key is {@code partition_key}
 * (string) and sort key is {@code sort_key} (number). Calls KMS GenerateDataKey and Decrypt, and DynamoDB PutItem and
 * GetItem.
 */
public final class BasicPutGetExample {

  private BasicPutGetExample() {}

  public static void main(String[] args) {
    if (args.length != 2) {
      throw new IllegalArgumentException("Arguments: <kms-key-arn> <table-name>");
    }
    run(args[0], args[1]);
  }

  public static void run(String kmsKeyArn, String tableName) {
    // 1. Create the keyring.
    // The MRK multi keyring handles single- and multi-Region keys; it creates its clients and closes them on close.
    try (AwsKmsMrkMultiKeyring keyring = AwsKmsMrkMultiKeyring.builder().generator(kmsKeyArn).build()) {
      // 2. Choose how each attribute is protected.
      // The primary key is always signed and never encrypted, since DynamoDB must read it to find the item.
      ItemEncryptionSchema schema = ItemEncryptionSchema
        .builder()
        .partitionKeyName("partition_key")
        .sortKeyName("sort_key")
        .encryptAndSign("attribute1")
        .signOnly("attribute2")
        .doNothingPrefix(":")
        .build();

      // 3. Configure the table, and a DynamoDB client that encrypts and decrypts its items.
      // Keep the logical table name when a table is restored or renamed: it is bound into every item.
      DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
        .builder()
        .tableName(tableName)
        .logicalTableName(tableName)
        .schema(schema)
        .keyring(keyring)
        .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384)
        .build();
      DynamoDbEncryptionInterceptor interceptor = DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();
      try (
        DynamoDbClient ddbClient = DynamoDbClient
          .builder()
          .overrideConfiguration(o -> o.addExecutionInterceptor(interceptor))
          .build();
        DynamoDbClient plainDdbClient = DynamoDbClient.create()
      ) {
        // 4. Put the item, and get it back with a strongly consistent read, since it follows the write at once.
        Map<String, AttributeValue> item = key("BasicPutGetExample", "0");
        item.put("attribute1", AttributeValue.builder().s("encrypt and sign me!").build());
        item.put("attribute2", AttributeValue.builder().s("sign me!").build());
        item.put(":attribute3", AttributeValue.builder().s("ignore me!").build());
        ddbClient.putItem(b -> b.tableName(tableName).item(item));
        Map<String, AttributeValue> returned = ddbClient
          .getItem(b -> b.tableName(tableName).key(key("BasicPutGetExample", "0")).consistentRead(true))
          .item();
        if (!"encrypt and sign me!".equals(returned.get("attribute1").s())) {
          throw new IllegalStateException("The item did not decrypt to what was put");
        }

        // 5. Without the interceptor: attribute1 is stored as ciphertext and attribute2 in the clear,
        // with the signature's header and footer attributes next to them.
        Map<String, AttributeValue> stored = plainDdbClient
          .getItem(b -> b.tableName(tableName).key(key("BasicPutGetExample", "0")).consistentRead(true))
          .item();
        AttributeValue storedAttribute1 = stored.get("attribute1");
        AttributeValue storedAttribute2 = stored.get("attribute2");
        if (
          storedAttribute1 == null ||
          storedAttribute1.b() == null ||
          storedAttribute1.b().asUtf8String().contains("encrypt and sign me!") ||
          storedAttribute2 == null ||
          !"sign me!".equals(storedAttribute2.s()) ||
          !stored.containsKey("aws_dbe_head") ||
          !stored.containsKey("aws_dbe_foot")
        ) {
          throw new IllegalStateException("The stored item is not protected as configured");
        }
      }
    }
  }

  private static Map<String, AttributeValue> key(String partitionKey, String sortKey) {
    Map<String, AttributeValue> key = new HashMap<>();
    key.put("partition_key", AttributeValue.builder().s(partitionKey).build());
    key.put("sort_key", AttributeValue.builder().n(sortKey).build());
    return key;
  }
}
