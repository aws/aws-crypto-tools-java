package software.amazon.cryptography.dbesdk.examples.searchableencryption;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconKeySource;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconStyle;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.CompoundBeacon;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.EncryptedPart;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.SignedPart;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.StandardBeacon;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;

/*
 This example demonstrates how to use Beacons Styles on Standard Beacons on encrypted attributes,
 put an item with the beacon, and query against that beacon. This example follows a use case of a
 database that stores food information. This is an extension of the
 "BasicSearchableEncryptionExample" in this directory and uses the same table schema.

 Running this example requires access to a DynamoDB table with the following key configuration:
   - Partition key is named "work_id" with type (S)
   - Sort key is named "inspection_date" with type (S)

 In this example for storing food information, this schema is utilized for the data:
  - "work_id" stores a unique identifier for a unit inspection work order (v4 UUID)
  - "inspection_date" stores an ISO 8601 date for the inspection (YYYY-MM-DD)
  - "fruit" stores one type of fruit
  - "basket" stores a set of types of fruit
  - "dessert" stores one type of dessert
  - "veggies" stores a set of types of vegetable
  - "work_type" stores a unit inspection category

 The example requires the following ordered input command line parameters:
   1. DynamoDB table name for table to put/query data from
   2. Branch key ID for a branch key that was previously created in your key store. See the
      CreateKeyStoreKeyExample.
   3. Branch key wrapping KMS key ARN for the KMS key used to create the branch key with ID
      provided in arg 2
   4. Branch key DynamoDB table ARN for the DynamoDB table representing the branch key store
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
    final StandardBeacon fruitBeacon = StandardBeacon
      .builder()
      .name("fruit")
      .bitLength(30)
      .build();

    // The basket beacon allows searching on the encrypted basket attribute
    // basket is used as a Set, and therefore needs a beacon style to reflect that.
    // Further, we need to be able to compare the items in basket to the fruit attribute
    // so we `share` this beacon with `fruit`.
    // Since we need both of these things, we use the SharedSet style.
    final StandardBeacon basketBeacon = StandardBeacon
      .builder()
      .name("basket")
      .bitLength(30)
      .style(BeaconStyle.sharedSet("fruit"))
      .build();

    // The dessert beacon allows searching on the encrypted dessert attribute
    // We need to be able to compare the dessert attribute to the fruit attribute
    // so we `share` this beacon with `fruit`.
    final StandardBeacon dessertBeacon = StandardBeacon
      .builder()
      .name("dessert")
      .bitLength(30)
      .style(BeaconStyle.shared("fruit"))
      .build();

    // The veggieBeacon allows searching on the encrypted veggies attribute
    // veggies is used as a Set, and therefore needs a beacon style to reflect that.
    final StandardBeacon veggieBeacon = StandardBeacon
      .builder()
      .name("veggies")
      .bitLength(30)
      .style(BeaconStyle.asSet())
      .build();

    // The workTypeBeacon allows searching on the encrypted work_type attribute
    // We only use it as part of the compound work_unit beacon,
    // so we disable its use as a standalone beacon
    final StandardBeacon workTypeBeacon = StandardBeacon
      .builder()
      .name("work_type")
      .bitLength(30)
      .style(BeaconStyle.partOnly())
      .build();

    // Here we build a compound beacon from work_id and work_type
    // If we had tried to make a StandardBeacon from work_type, we would have seen an error
    // because work_type is "PartOnly"
    final EncryptedPart workTypePart = EncryptedPart
      .builder()
      .name("work_type")
      .prefix("T-")
      .build();

    final SignedPart workIdPart = SignedPart
      .builder()
      .name("work_id")
      .prefix("I-")
      .build();

    final CompoundBeacon workUnitBeacon = CompoundBeacon
      .builder()
      .name("work_unit")
      .split(".")
      .encrypted(workTypePart)
      .signed(workIdPart)
      .build();

    // 2. Configure the Keystore
    //    These are the same constructions as in the Basic example, which describes these in more detail.
    final BranchKeyStore keyStore = BranchKeyStore
      .builder()
      .kmsClient(KmsClient.create())
      .ddbClient(DynamoDbClient.create())
      .ddbTableName(keyStoreTableName)
      .logicalKeyStoreName(keyStoreTableName)
      .kmsConfiguration(KmsConfiguration.kmsKeyArn(branchKeyWrappingKmsKeyArn))
      .build();

    // 3. Create BeaconConfig.
    //    This is similar to the Basic example
    final BeaconConfig beaconConfig = BeaconConfig
      .builder()
      .standardBeacons(fruitBeacon, basketBeacon, dessertBeacon, veggieBeacon, workTypeBeacon)
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
    final Keyring kmsKeyring = AwsKmsHierarchicalKeyring
      .builder()
      .branchKeyId(branchKeyId)
      .keyStore(keyStore)
      .ttl(Duration.ofSeconds(6000))
      .build();

    // 5. Decide how each attribute of your items is protected. Give each attribute one of these
    //    actions:
    //    - encryptAndSign: the value is encrypted, so it cannot be read without the keys your
    //      keyring uses, and it is covered by the item's signature, so any change to it is detected
    //      when the item is read.
    //    - signOnly: the value is stored as plain, readable text, but it is covered by the
    //      signature, so any change to it is detected.
    //    - signAndIncludeInEncryptionContext: like signOnly, and the value is also handed to your
    //      keyring each time the item is encrypted or decrypted, for example so that a branch key
    //      ID supplier can pick a different key for each tenant. Using this action also requires
    //      signAndIncludePrimaryKeysInEncryptionContext(true) (see below).
    //    - doNothing: the value is stored as plain text and is not covered by the signature, so a
    //      change to it is NOT detected.
    //    Every attribute you write must have an action; writing an item with any other attribute
    //    fails.
    //
    //    Do not give the partition key or the sort key (together, the table's primary key) an
    //    action. DynamoDB needs to read them to find the item, so they can never be encrypted, and
    //    the library always signs them for you. By default they are signed like signOnly, and their
    //    values are still handed to your keyring, in an encoded form. If you call
    //    signAndIncludePrimaryKeysInEncryptionContext(true), they are signed like
    //    signAndIncludeInEncryptionContext instead: their values are handed to your keyring as
    //    plain text, and you can give other attributes the signAndIncludeInEncryptionContext
    //    action.

    // Build the schema from these choices.
    final ItemEncryptionSchema schema = ItemEncryptionSchema
      .builder()
      .partitionKeyName("work_id")
      .sortKeyName("inspection_date")
      // Beaconized attributes must be encrypted
      .encryptAndSign("dessert", "fruit", "basket", "veggies", "work_type")
      .build();

    // 6. Create the DynamoDB Encryption configuration for the table we will be writing to.
    //    The beacon configuration is added to the table configuration.
    final DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .logicalTableName(tableName)
      .schema(schema)
      .keyring(kmsKeyring)
      .beaconConfig(beaconConfig)
      .build();

    // Generate unique work_id values for this run to avoid collisions with stale items
    final String workId1 = UUID.randomUUID().toString();
    final String workId2 = UUID.randomUUID().toString();

    // 7. Create item one, specifically with "dessert != fruit", and "fruit in basket".
    final Map<String, AttributeValue> item1 = new HashMap<>();
    item1.put("work_id", AttributeValue.builder().s(workId1).build());
    item1.put(
      "inspection_date",
      AttributeValue.builder().s("2023-06-13").build()
    );
    item1.put("dessert", AttributeValue.builder().s("cake").build());
    item1.put("fruit", AttributeValue.builder().s("banana").build());
    item1.put(
      "basket",
      AttributeValue.builder().ss("apple", "banana", "pear").build()
    );
    item1.put(
      "veggies",
      AttributeValue.builder().ss("beans", "carrots", "celery").build()
    );
    item1.put("work_type", AttributeValue.builder().s("small").build());

    // 8. Create item two, specifically with "dessert == fruit", and "fruit not in basket".
    final Map<String, AttributeValue> item2 = new HashMap<>();
    item2.put("work_id", AttributeValue.builder().s(workId2).build());
    item2.put(
      "inspection_date",
      AttributeValue.builder().s("2023-06-13").build()
    );
    item2.put("fruit", AttributeValue.builder().s("orange").build());
    item2.put("dessert", AttributeValue.builder().s("orange").build());
    item2.put(
      "basket",
      AttributeValue
        .builder()
        .ss("blackberry", "blueberry", "strawberry")
        .build()
    );
    item2.put(
      "veggies",
      AttributeValue.builder().ss("beans", "carrots", "peas").build()
    );
    item2.put("work_type", AttributeValue.builder().s("large").build());
    // 9. Create the DynamoDB Encryption Interceptor
    final DynamoDbEncryptionInterceptor encryptionInterceptor =
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
      PutItemRequest putRequest = PutItemRequest
        .builder()
        .tableName(tableName)
        .item(item1)
        .build();

      dynamoDbClient.putItem(putRequest);

      putRequest =
        PutItemRequest.builder().tableName(tableName).item(item2).build();

      dynamoDbClient.putItem(putRequest);

      // These filters ensure scans only match items created by this test run.
      final String widFilter = "work_id IN (:wid1, :wid2)";
      final Map<String, AttributeValue> widValues = new HashMap<>();
      widValues.put(":wid1", AttributeValue.builder().s(workId1).build());
      widValues.put(":wid2", AttributeValue.builder().s(workId2).build());
      try {
        // 12. Test the first type of Set operation :
        // Select records where the basket attribute holds a particular value
        Map<String, AttributeValue> expressionAttributeValues = new HashMap<>(
          widValues
        );
        expressionAttributeValues.put(
          ":value",
          AttributeValue.builder().s("banana").build()
        );

        ScanRequest scanRequest = ScanRequest
          .builder()
          .tableName(tableName)
          .filterExpression(widFilter + " AND contains(basket, :value)")
          .expressionAttributeValues(expressionAttributeValues)
          .build();

        ScanResponse scanResponse = dynamoDbClient.scan(scanRequest);
        assert scanResponse.items().size() == 1;
        assert scanResponse.items().get(0).equals(item1);

        // 13. Test the second type of Set operation :
        // Select records where the basket attribute holds the fruit attribute
        scanRequest =
          ScanRequest
            .builder()
            .tableName(tableName)
            .filterExpression(widFilter + " AND contains(basket, fruit)")
            .expressionAttributeValues(widValues)
            .build();

        scanResponse = dynamoDbClient.scan(scanRequest);
        assert scanResponse.items().size() == 1;
        assert scanResponse.items().get(0).equals(item1);

        // 14. Test the third type of Set operation :
        // Select records where the fruit attribute exists in a particular set
        expressionAttributeValues = new HashMap<>(widValues);
        expressionAttributeValues.put(
          ":value",
          AttributeValue.builder().ss("boysenberry", "grape", "orange").build()
        );

        scanRequest =
          ScanRequest
            .builder()
            .tableName(tableName)
            .filterExpression(widFilter + " AND contains(:value, fruit)")
            .expressionAttributeValues(expressionAttributeValues)
            .build();

        scanResponse = dynamoDbClient.scan(scanRequest);
        assert scanResponse.items().size() == 1;
        assert scanResponse.items().get(0).equals(item2);

        // Test a Shared search. Select records where the dessert attribute matches the fruit attribute
        scanRequest =
          ScanRequest
            .builder()
            .tableName(tableName)
            .filterExpression(widFilter + " AND dessert = fruit")
            .expressionAttributeValues(widValues)
            .build();

        scanResponse = dynamoDbClient.scan(scanRequest);
        assert scanResponse.items().size() == 1;
        assert scanResponse.items().get(0).equals(item2);

        // 15. Test the AsSet attribute 'veggies' :
        // Select records where the veggies attribute holds a particular value
        expressionAttributeValues = new HashMap<>(widValues);
        expressionAttributeValues.put(
          ":value",
          AttributeValue.builder().s("peas").build()
        );

        scanRequest =
          ScanRequest
            .builder()
            .tableName(tableName)
            .filterExpression(widFilter + " AND contains(veggies, :value)")
            .expressionAttributeValues(expressionAttributeValues)
            .build();

        scanResponse = dynamoDbClient.scan(scanRequest);
        assert scanResponse.items().size() == 1;
        assert scanResponse.items().get(0).equals(item2);

        // 16. Test the compound beacon 'work_unit' :
        expressionAttributeValues = new HashMap<>(widValues);
        expressionAttributeValues.put(
          ":value",
          AttributeValue.builder().s("I-" + workId1 + ".T-small").build()
        );

        scanRequest =
          ScanRequest
            .builder()
            .tableName(tableName)
            .filterExpression(widFilter + " AND work_unit = :value")
            .expressionAttributeValues(expressionAttributeValues)
            .build();

        scanResponse = dynamoDbClient.scan(scanRequest);
        assert scanResponse.items().size() == 1;
        assert scanResponse.items().get(0).equals(item1);
      } finally {
        // Clean up: delete both items using a plain DynamoDB client
        try (DynamoDbClient plainDynamoDbClient = DynamoDbClient.create()) {
          final Map<String, AttributeValue> key1 = new HashMap<>();
          key1.put("work_id", AttributeValue.builder().s(workId1).build());
          key1.put(
            "inspection_date",
            AttributeValue.builder().s("2023-06-13").build()
          );
          plainDynamoDbClient.deleteItem(
            DeleteItemRequest.builder().tableName(tableName).key(key1).build()
          );
          final Map<String, AttributeValue> key2 = new HashMap<>();
          key2.put("work_id", AttributeValue.builder().s(workId2).build());
          key2.put(
            "inspection_date",
            AttributeValue.builder().s("2023-06-13").build()
          );
          plainDynamoDbClient.deleteItem(
            DeleteItemRequest.builder().tableName(tableName).key(key2).build()
          );
        }
      }
    }
  }

  public static void main(final String[] args) {
    if (args.length < 4) {
      throw new IllegalArgumentException(
        "To run this example, include tableName as args[0], branchKeyId as args[1], " +
        "branchKeyWrappingKmsKeyArn as args[2], and keyStoreTableName as args[3]"
      );
    }
    final String tableName = args[0];
    final String branchKeyId = args[1];
    final String branchKeyWrappingKmsKeyArn = args[2];
    final String keyStoreTableName = args[3];
    putAndScanItems(
      tableName,
      branchKeyId,
      branchKeyWrappingKmsKeyArn,
      keyStoreTableName
    );
  }
}
