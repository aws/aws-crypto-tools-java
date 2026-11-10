// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.dbesdk;

import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconKeySource;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.StandardBeacon;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;

/**
 * Queries an encrypted attribute through a standard beacon: a truncated HMAC of the value, under a key derived from a
 * beacon key in the branch key store, that DynamoDB can index.
 *
 * <p>Arguments: a table whose partition key is {@code work_id} (string) and sort key is {@code inspection_date}
 * (string), with a global secondary index {@code last4-index} on {@code aws_dbe_b_inspector_id_last4} (string) that
 * projects all attributes, so query results can be decrypted; and
 * the key store's table name, logical name, KMS key ARN in the SDK's default Region, and an existing branch key id.
 */
public final class SearchableEncryptionExample {

  private static final String GSI_NAME = "last4-index";

  private SearchableEncryptionExample() {}

  public static void main(String[] args) throws InterruptedException {
    if (args.length != 5) {
      throw new IllegalArgumentException(
        "Arguments: <table-name> <key-store-table> <logical-key-store-name> <kms-key-arn> <branch-key-id>"
      );
    }
    try (KmsClient kmsClient = KmsClient.create(); DynamoDbClient keyStoreDdbClient = DynamoDbClient.create()) {
      run(args[0], args[1], args[2], args[3], args[4], kmsClient, keyStoreDdbClient);
    }
  }

  public static void run(
    String tableName,
    String keyStoreTableName,
    String logicalKeyStoreName,
    String kmsKeyArn,
    String branchKeyId,
    KmsClient kmsClient,
    DynamoDbClient keyStoreDdbClient
  ) throws InterruptedException {
    try (
      BranchKeyStore keyStore = BranchKeyStore
        .builder()
        .ddbTableName(keyStoreTableName)
        .logicalKeyStoreName(logicalKeyStoreName)
        .kmsConfiguration(KmsConfiguration.kmsKeyArn(kmsKeyArn))
        .kmsClient(kmsClient)
        .ddbClient(keyStoreDdbClient)
        .build()
    ) {
      // 1. Fail at startup, not on the first write, if the beacon key is missing or this caller may not use it.
      // Every branch key has a beacon key with the same id. No way to release the returned key: its materials own it.
      keyStore.getBeaconKey(b -> b.branchKeyIdentifier(branchKeyId));

      // 2. Configure the beacon.
      // Fewer bits give more false matches but reveal less about the value; size it to the number of distinct values.
      StandardBeacon last4Beacon = StandardBeacon.builder().name("inspector_id_last4").bitLength(10).build();
      // The DB-ESDK caches only the HMAC keys it derives from the beacon key (BeaconKeyMaterials.toHmacKeysOnly);
      // the TTL bounds how long they are used without another KMS call.
      BeaconConfig beaconConfig = BeaconConfig
        .builder()
        .standardBeacons(last4Beacon)
        .keyStore(keyStore)
        .keySource(BeaconKeySource.singleBeaconKey(branchKeyId).cacheTtl(Duration.ofMinutes(10)).build())
        .build();

      // 3. Configure the table, with a hierarchical keyring for the same branch key.
      Keyring keyring = AwsKmsHierarchicalKeyring
        .builder()
        .keyStore(keyStore)
        .branchKeyId(branchKeyId)
        .ttl(Duration.ofMinutes(10))
        .build();
      ItemEncryptionSchema schema = ItemEncryptionSchema
        .builder()
        .partitionKeyName("work_id")
        .sortKeyName("inspection_date")
        .encryptAndSign("inspector_id_last4")
        .build();
      DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
        .builder()
        .tableName(tableName)
        .logicalTableName(tableName)
        .schema(schema)
        .keyring(keyring)
        .beaconConfig(beaconConfig)
        .build();
      DynamoDbEncryptionInterceptor interceptor = DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();

      try (
        DynamoDbClient ddbClient = DynamoDbClient
          .builder()
          .overrideConfiguration(o -> o.addExecutionInterceptor(interceptor))
          .build()
      ) {
        // 4. Put an item; the interceptor also writes the beacon attribute aws_dbe_b_inspector_id_last4.
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("work_id", AttributeValue.builder().s("1313ba89-5661-41eb-ba6c-cb1b4cb67b2d").build());
        item.put("inspection_date", AttributeValue.builder().s("2023-06-13").build());
        item.put("inspector_id_last4", AttributeValue.builder().s("4321").build());
        ddbClient.putItem(b -> b.tableName(tableName).item(item));

        // 5. Query by the plaintext value; the interceptor replaces it with its beacon.
        // An index is eventually consistent, so poll briefly for the new item.
        Map<String, String> names = Collections.singletonMap("#last4", "inspector_id_last4");
        Map<String, AttributeValue> values = Collections.singletonMap(
          ":last4",
          AttributeValue.builder().s("4321").build()
        );
        for (int attempt = 0; attempt < 10; attempt++) {
          List<Map<String, AttributeValue>> results = ddbClient
            .query(b ->
              b
                .tableName(tableName)
                .indexName(GSI_NAME)
                .keyConditionExpression("#last4 = :last4")
                .expressionAttributeNames(names)
                .expressionAttributeValues(values)
            )
            .items();
          for (Map<String, AttributeValue> result : results) {
            if (item.get("work_id").equals(result.get("work_id"))) {
              if (!"4321".equals(result.get("inspector_id_last4").s())) {
                throw new IllegalStateException("The queried item did not decrypt to what was put");
              }
              return;
            }
          }
          Thread.sleep(100);
        }
        throw new IllegalStateException("The query did not find the item");
      }
    }
  }
}
