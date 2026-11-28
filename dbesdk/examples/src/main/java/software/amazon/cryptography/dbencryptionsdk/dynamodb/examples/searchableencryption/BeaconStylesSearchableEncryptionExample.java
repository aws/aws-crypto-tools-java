package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.searchableencryption;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconKeySource;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconStyle;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.CompoundBeacon;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.EncryptedPart;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.SignedPart;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.StandardBeacon;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;
import software.amazon.cryptography.materialproviders.keystore.DynamoDbKeyStore;
import software.amazon.cryptography.materialproviders.keystore.KmsConfiguration;

/**
 * This example demonstrates how to use Beacons Styles on Standard Beacons on encrypted attributes,
 * put an item with the beacon, and query against that beacon. This example follows a use case of a
 * database that stores food information. This is an extension of the
 * "BasicSearchableEncryptionExample" in this directory and uses the same table schema.
 *
 * <p>Running this example requires access to a DynamoDB table with the following key configuration:
 *   - Partition key is named "work_id" with type (S)
 *   - Sort key is named "inspection_date" with type (S)
 *
 * <p>In this example for storing food information, this schema is utilized for the data:
 *  - "work_id" stores a unique identifier for a unit inspection work order (v4 UUID)
 *  - "inspection_date" stores an ISO 8601 date for the inspection (YYYY-MM-DD)
 *  - "fruit" stores one type of fruit
 *  - "basket" stores a set of types of fruit
 *  - "dessert" stores one type of dessert
 *  - "veggies" stores a set of types of vegetable
 *  - "work_type" stores a unit inspection category
 *
 * <p>The example requires the following ordered input command line parameters:
 *   1. DynamoDB table name for table to put/query data from
 *   2. Branch key ID for a branch key that was previously created in your key store. See the
 *      CreateKeyStoreKeyExample.
 *   3. Branch key wrapping KMS key ARN for the KMS key used to create the branch key with ID
 *      provided in arg 2
 *   4. Branch key DynamoDB table ARN for the DynamoDB table representing the branch key store
 */
public class BeaconStylesSearchableEncryptionExample {

  public static void putAndScanItems(
    String tableName,
    String branchKeyId,
    String branchKeyWrappingKmsKeyArn,
    String keyStoreTableName
  ) {
    // 1. Create Beacons.
    // The fruit beacon allows searching on the encrypted fruit attribute
    // We have selected 30 as an example beacon length, but you should go to
    // https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/choosing-beacon-length.html
    // when creating your beacons.
    StandardBeacon fruitBeacon = StandardBeacon
      .builder()
      .name("fruit")
      .bitLength(30)
      .build();

    // The basket beacon allows searching on the encrypted basket attribute
    // basket is used as a Set, and therefore needs a beacon style to reflect that.
    // Further, we need to be able to compare the items in basket to the fruit attribute
    // so we `share` this beacon with `fruit`.
    // Since we need both of these things, we use the BeaconStyle.sharedSet style.
    StandardBeacon basketBeacon = StandardBeacon
      .builder()
      .name("basket")
      .bitLength(30)
      .style(BeaconStyle.sharedSet(fruitBeacon))
      .build();

    // The dessert beacon allows searching on the encrypted dessert attribute
    // We need to be able to compare the dessert attribute to the fruit attribute
    // so we `share` this beacon with `fruit`.
    StandardBeacon dessertBeacon = StandardBeacon
      .builder()
      .name("dessert")
      .bitLength(30)
      .style(BeaconStyle.shared(fruitBeacon))
      .build();

    // The veggieBeacon allows searching on the encrypted veggies attribute
    // veggies is used as a Set, and therefore needs a beacon style to reflect that.
    StandardBeacon veggieBeacon = StandardBeacon
      .builder()
      .name("veggies")
      .bitLength(30)
      .style(BeaconStyle.asSet())
      .build();

    // The workTypeBeacon allows searching on the encrypted work_type attribute
    // We only use it as part of the compound work_unit beacon,
    // so we disable its use as a standalone beacon
    StandardBeacon workTypeBeacon = StandardBeacon
      .builder()
      .name("work_type")
      .bitLength(30)
      .style(BeaconStyle.partOnly())
      .build();

    // Here we build a compound beacon from work_id and work_type
    // If we had tried to make a StandardBeacon from work_type, we would have seen an error
    // because work_type uses the BeaconStyle.partOnly style.
    // The encrypted part takes the standard beacon whose value it holds.
    EncryptedPart workTypePart = EncryptedPart
      .builder()
      .beacon(workTypeBeacon)
      .prefix("T-")
      .build();

    SignedPart workIdPart = SignedPart
      .builder()
      .name("work_id")
      .prefix("I-")
      .build();

    CompoundBeacon workUnitBeacon = CompoundBeacon
      .builder()
      .name("work_unit")
      .separator('.')
      .encrypted(workTypePart)
      .signed(workIdPart)
      .build();

    // 2. Configure the Keystore
    //    These are the same constructions as in the Basic example, which describes these in more detail.
    // The DynamoDB and AWS KMS clients the keystore uses. Both are optional: without them, the
    // keystore creates its own in the region of the KMS key ARN. KmsClient.create() and
    // DynamoDbClient.create() use your environment's default region and credentials instead.
    // The try block closes them when it ends, so everything that uses the keystore stays inside it.
    try (
      DynamoDbClient keyStoreDynamoDbClient = DynamoDbClient.create();
      KmsClient keyStoreKmsClient = KmsClient.create()
    ) {
      DynamoDbKeyStore keyStore = DynamoDbKeyStore
        .builder()
        .ddbTableName(keyStoreTableName)
        .logicalKeyStoreName(keyStoreTableName)
        .kmsConfiguration(
          KmsConfiguration.kmsKeyArn(branchKeyWrappingKmsKeyArn)
        )
        .ddbClient(keyStoreDynamoDbClient)
        .kmsClient(keyStoreKmsClient)
        .build();

      // 3. Create BeaconConfig.
      //    This is similar to the Basic example
      BeaconConfig beaconConfig = BeaconConfig
        .builder()
        .standardBeacons(
          fruitBeacon,
          basketBeacon,
          dessertBeacon,
          veggieBeacon,
          workTypeBeacon
        )
        .compoundBeacons(workUnitBeacon)
        .keyStore(keyStore)
        .keySource(
          BeaconKeySource
            .singleBeaconKey(branchKeyId)
            .cacheTtl(Duration.ofSeconds(6000))
            .build()
        )
        .build();

      // 4. Create a Hierarchical Keyring
      //    This is the same configuration as in the Basic example.
      Keyring kmsKeyring = AwsKmsHierarchicalKeyring
        .builder()
        .branchKeyId(branchKeyId)
        .keyStore(keyStore)
        .ttl(Duration.ofSeconds(6000))
        .build();

      // 5. Decide how each attribute of your items is protected. BasicPutGetExample
      //    explains each action (encryptAndSign, signOnly, signAndIncludeInEncryptionContext,
      //    doNothing), and why the partition and sort keys get none.
      //    Every attribute you write must have an action; writing an item with any other attribute
      //    fails.

      // Build the schema from these choices.
      ItemEncryptionSchema schema = ItemEncryptionSchema
        .builder()
        .partitionKeyName("work_id")
        .sortKeyName("inspection_date")
        // Beaconized attributes must be encrypted
        .encryptAndSign("dessert", "fruit", "basket", "veggies", "work_type")
        .build();

      // 6. Create the DynamoDB Encryption configuration for the table we will be writing to.
      //    The beacon configuration is added to the table configuration.
      DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
        .builder()
        .tableName(tableName)
        .schema(schema)
        .keyring(kmsKeyring)
        .beaconConfig(beaconConfig)
        .build();

      // Generate unique work_id values for this run to avoid collisions with stale items
      String workId1 = UUID.randomUUID().toString();
      String workId2 = UUID.randomUUID().toString();

      // 7. Create item one, specifically with "dessert != fruit", and "fruit in basket".
      Map<String, AttributeValue> item1 = Map.of(
        "work_id",
        AttributeValue.fromS(workId1),
        "inspection_date",
        AttributeValue.fromS("2023-06-13"),
        "dessert",
        AttributeValue.fromS("cake"),
        "fruit",
        AttributeValue.fromS("banana"),
        "basket",
        AttributeValue.fromSs(List.of("apple", "banana", "pear")),
        "veggies",
        AttributeValue.fromSs(List.of("beans", "carrots", "celery")),
        "work_type",
        AttributeValue.fromS("small")
      );

      // 8. Create item two, specifically with "dessert == fruit", and "fruit not in basket".
      Map<String, AttributeValue> item2 = Map.of(
        "work_id",
        AttributeValue.fromS(workId2),
        "inspection_date",
        AttributeValue.fromS("2023-06-13"),
        "fruit",
        AttributeValue.fromS("orange"),
        "dessert",
        AttributeValue.fromS("orange"),
        "basket",
        AttributeValue.fromSs(List.of("blackberry", "blueberry", "strawberry")),
        "veggies",
        AttributeValue.fromSs(List.of("beans", "carrots", "peas")),
        "work_type",
        AttributeValue.fromS("large")
      );
      // 9. Create the DynamoDB Encryption Interceptor
      DynamoDbEncryptionInterceptor encryptionInterceptor =
        DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();

      // 10. Create a new AWS SDK DynamoDB client using the DynamoDB Encryption Interceptor above
      try (
        DynamoDbClient dynamoDbClient = DynamoDbClient
          .builder()
          .overrideConfiguration(overrides ->
            overrides.addExecutionInterceptor(encryptionInterceptor)
          )
          .build()
      ) {
        // 11. Add the two items
        PutItemRequest item1PutRequest = PutItemRequest
          .builder()
          .tableName(tableName)
          .item(item1)
          .build();

        dynamoDbClient.putItem(item1PutRequest);

        PutItemRequest item2PutRequest = PutItemRequest
          .builder()
          .tableName(tableName)
          .item(item2)
          .build();

        dynamoDbClient.putItem(item2PutRequest);

        // This filter limits each scan to the two items this example wrote, so other items in the
        // table do not change the results.
        String workIdFilter = "work_id IN (:workId1, :workId2)";
        Map<String, AttributeValue> workIdValues = Map.of(
          ":workId1",
          AttributeValue.fromS(workId1),
          ":workId2",
          AttributeValue.fromS(workId2)
        );
        try {
          // 12. Test the first type of Set operation :
          // Select records where the basket attribute holds a particular value
          Map<String, AttributeValue> basketValues = Map.of(
            ":workId1",
            AttributeValue.fromS(workId1),
            ":workId2",
            AttributeValue.fromS(workId2),
            ":value",
            AttributeValue.fromS("banana")
          );

          ScanRequest basketValueScanRequest = ScanRequest
            .builder()
            .tableName(tableName)
            .filterExpression(workIdFilter + " AND contains(basket, :value)")
            .expressionAttributeValues(basketValues)
            .build();

          ScanResponse basketValueScanResponse = dynamoDbClient.scan(
            basketValueScanRequest
          );
          assert basketValueScanResponse.items().size() == 1;
          assert basketValueScanResponse.items().get(0).equals(item1);

          // 13. Test the second type of Set operation :
          // Select records where the basket attribute holds the fruit attribute
          ScanRequest basketFruitScanRequest = ScanRequest
            .builder()
            .tableName(tableName)
            .filterExpression(workIdFilter + " AND contains(basket, fruit)")
            .expressionAttributeValues(workIdValues)
            .build();

          ScanResponse basketFruitScanResponse = dynamoDbClient.scan(
            basketFruitScanRequest
          );
          assert basketFruitScanResponse.items().size() == 1;
          assert basketFruitScanResponse.items().get(0).equals(item1);

          // 14. Test the third type of Set operation :
          // Select records where the fruit attribute exists in a particular set
          Map<String, AttributeValue> fruitSetValues = Map.of(
            ":workId1",
            AttributeValue.fromS(workId1),
            ":workId2",
            AttributeValue.fromS(workId2),
            ":value",
            AttributeValue.fromSs(List.of("boysenberry", "grape", "orange"))
          );

          ScanRequest fruitInSetScanRequest = ScanRequest
            .builder()
            .tableName(tableName)
            .filterExpression(workIdFilter + " AND contains(:value, fruit)")
            .expressionAttributeValues(fruitSetValues)
            .build();

          ScanResponse fruitInSetScanResponse = dynamoDbClient.scan(
            fruitInSetScanRequest
          );
          assert fruitInSetScanResponse.items().size() == 1;
          assert fruitInSetScanResponse.items().get(0).equals(item2);

          // Test a Shared search. Select records where the dessert attribute matches the fruit attribute
          ScanRequest dessertMatchesFruitScanRequest = ScanRequest
            .builder()
            .tableName(tableName)
            .filterExpression(workIdFilter + " AND dessert = fruit")
            .expressionAttributeValues(workIdValues)
            .build();

          ScanResponse dessertMatchesFruitScanResponse = dynamoDbClient.scan(
            dessertMatchesFruitScanRequest
          );
          assert dessertMatchesFruitScanResponse.items().size() == 1;
          assert dessertMatchesFruitScanResponse.items().get(0).equals(item2);

          // 15. Test the attribute 'veggies', whose beacon uses the BeaconStyle.asSet style:
          // Select records where the veggies attribute holds a particular value
          Map<String, AttributeValue> veggiesValues = Map.of(
            ":workId1",
            AttributeValue.fromS(workId1),
            ":workId2",
            AttributeValue.fromS(workId2),
            ":value",
            AttributeValue.fromS("peas")
          );

          ScanRequest veggiesValueScanRequest = ScanRequest
            .builder()
            .tableName(tableName)
            .filterExpression(workIdFilter + " AND contains(veggies, :value)")
            .expressionAttributeValues(veggiesValues)
            .build();

          ScanResponse veggiesValueScanResponse = dynamoDbClient.scan(
            veggiesValueScanRequest
          );
          assert veggiesValueScanResponse.items().size() == 1;
          assert veggiesValueScanResponse.items().get(0).equals(item2);

          // 16. Test the compound beacon 'work_unit' :
          Map<String, AttributeValue> workUnitValues = Map.of(
            ":workId1",
            AttributeValue.fromS(workId1),
            ":workId2",
            AttributeValue.fromS(workId2),
            ":value",
            AttributeValue.fromS("I-" + workId1 + ".T-small")
          );

          ScanRequest workUnitScanRequest = ScanRequest
            .builder()
            .tableName(tableName)
            .filterExpression(workIdFilter + " AND work_unit = :value")
            .expressionAttributeValues(workUnitValues)
            .build();

          ScanResponse workUnitScanResponse = dynamoDbClient.scan(
            workUnitScanRequest
          );
          assert workUnitScanResponse.items().size() == 1;
          assert workUnitScanResponse.items().get(0).equals(item1);
        } finally {
          // Clean up: delete both items using a plain DynamoDB client
          try (DynamoDbClient plainDynamoDbClient = DynamoDbClient.create()) {
            Map<String, AttributeValue> key1 = Map.of(
              "work_id",
              AttributeValue.fromS(workId1),
              "inspection_date",
              AttributeValue.fromS("2023-06-13")
            );
            plainDynamoDbClient.deleteItem(
              DeleteItemRequest.builder().tableName(tableName).key(key1).build()
            );
            Map<String, AttributeValue> key2 = Map.of(
              "work_id",
              AttributeValue.fromS(workId2),
              "inspection_date",
              AttributeValue.fromS("2023-06-13")
            );
            plainDynamoDbClient.deleteItem(
              DeleteItemRequest.builder().tableName(tableName).key(key2).build()
            );
          }
        }
      }
    }
  }

  public static void main(String[] args) {
    if (args.length < 4) {
      throw new IllegalArgumentException(
        "To run this example, include tableName as args[0], branchKeyId as args[1], " +
        "branchKeyWrappingKmsKeyArn as args[2], and keyStoreTableName as args[3]"
      );
    }
    String tableName = args[0];
    String branchKeyId = args[1];
    String branchKeyWrappingKmsKeyArn = args[2];
    String keyStoreTableName = args[3];
    putAndScanItems(
      tableName,
      branchKeyId,
      branchKeyWrappingKmsKeyArn,
      keyStoreTableName
    );
  }
}
