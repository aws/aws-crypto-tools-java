package software.amazon.cryptography.dbesdk.examples.searchableencryption;

import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconKeySource;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconStyle;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.CompoundBeacon;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.Constructor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ConstructorPart;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.EncryptedPart;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.StandardBeacon;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.transforms.DynamoDbEncryptionTransforms;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;

/*
 This example demonstrates how to set up a compound beacon on encrypted attributes, put an item with
 the beacon, and query against that beacon. This example follows a use case of a database that
 stores unit inspection information. This is an extension of the "BasicSearchableEncryptionExample"
 in this directory. This example uses the same situation (storing unit inspection information) and
 the same table schema. However, this example uses a different Global Secondary Index (GSI) that is
 based on a compound beacon configuration composed of the `last4` and `unit` attributes.

 Running this example requires access to a DynamoDB table with the following key configuration:
   - Partition key is named "work_id" with type (S)
   - Sort key is named "inspection_date" with type (S)
 This table must have a Global Secondary Index (GSI) configured named "last4UnitCompound-index":
   - Partition key is named "aws_dbe_b_last4UnitCompound" with type (S)

 In this example for storing unit inspection information, this schema is utilized for the data:
  - "work_id" stores a unique identifier for a unit inspection work order (v4 UUID)
  - "inspection_date" stores an ISO 8601 date for the inspection (YYYY-MM-DD)
  - "inspector_id_last4" stores the last 4 digits of the ID of the inspector performing the work
  - "unit" stores a 12-digit serial number for the unit being inspected

 The example requires the following ordered input command line parameters:
   1. DynamoDB table name for table to put/query data from
   2. Branch key ID for a branch key that was previously created in your key store. See the
      CreateKeyStoreKeyExample.
   3. Branch key wrapping KMS key ARN for the KMS key used to create the branch key with ID
      provided in arg 2
   4. Branch key DynamoDB table ARN for the DynamoDB table representing the branch key store
*/

public class CompoundBeaconSearchableEncryptionExample {

  private static final String GSI_NAME = "last4UnitCompound-index";
  private static final int MAX_CONCURRENT_QUERY_THREADS = 10;
  private static final int TASK_COUNT = 2 * MAX_CONCURRENT_QUERY_THREADS;
  private static final int PUT_AND_QUERY_ROUNDS_PER_TASK = 20;

  public static void putAndQueryItem(
    String tableName,
    String branchKeyId,
    String branchKeyWrappingKmsKeyArn,
    String keyStoreTableName
  ) {
    // 1. Create Beacons.
    //    These are the same beacons as in the "BasicSearchableEncryptionExample" in this directory.
    //    See that file to see details on beacon construction and parameters.
    //    While we will not directly query against these beacons,
    //      you must create standard beacons on encrypted fields
    //      that we wish to use in compound beacons.
    //    We mark them both as PartOnly to enforce the fact that
    //      we will not directly query against these beacons.
    final StandardBeacon last4Beacon = StandardBeacon
      .builder()
      .name("inspector_id_last4")
      .bitLength(10)
      .style(BeaconStyle.partOnly())
      .build();
    final StandardBeacon unitBeacon = StandardBeacon
      .builder()
      .name("unit")
      .bitLength(30)
      .style(BeaconStyle.partOnly())
      .build();

    // 2. Define encrypted parts.
    //    Encrypted parts define the beacons that can be used to construct a compound beacon,
    //        and how the compound beacon prefixes those beacon values.
    // A encrypted part must receive:
    //  - name: Name of a standard beacon
    //  - prefix: Any string. This is plaintext that prefixes the beaconized value in the compound beacon.
    //            Prefixes must be unique across the configuration, and must not be a prefix of another prefix;
    //            i.e. for all configured prefixes, the first N characters of a prefix must not equal another prefix.
    // In practice, it is suggested to have a short value distinguishable from other parts served on the prefix.

    // For this example, we will choose "L-" as the prefix for "Last 4 digits of inspector ID".
    // With this prefix and the standard beacon's bit length definition (10), the beaconized
    //     version of the inspector ID's last 4 digits will appear as
    //     `L-000` to `L-3ff` inside a compound beacon.
    final EncryptedPart last4EncryptedPart = EncryptedPart
      .builder()
      .name("inspector_id_last4")
      .prefix("L-")
      .build();
    // For this example, we will choose "U-" as the prefix for "unit".
    // With this prefix and the standard beacon's bit length definition (30), a unit beacon will appear
    //     as `U-00000000` to `U-3fffffff` inside a compound beacon.
    final EncryptedPart unitEncryptedPart = EncryptedPart
      .builder()
      .name("unit")
      .prefix("U-")
      .build();

    final Constructor constructor = Constructor
      .builder()
      .parts(
        ConstructorPart
          .builder()
          .name("inspector_id_last4")
          .required(true)
          .build(),
        ConstructorPart
          .builder()
          // This name comes from the "EmployeeID" standard beacon.
          .name("unit")
          .required(true)
          .build()
      )
      .build();

    // 3. Define compound beacon.
    //    A compound beacon allows one to serve multiple beacons or attributes from a single index.
    //    A compound beacon must receive:
    //     - name: The name of the beacon. Compound beacon values will be written to `aws_dbe_b_[name]`.
    //     - split: A character separating parts in a compound beacon
    //    A compound beacon may also receive:
    //     - encrypted: A list of encrypted parts. This is effectively a list of beacons. We provide the list
    //                  that we created above.
    //     - constructors: A list of constructors. This is an ordered list of possible ways to create a beacon.
    //                     We have not defined any constructors here; see the complex example for how to do this.
    //                     The client will provide a default constructor, which will write a compound beacon as:
    //                     all signed parts in the order they are added to the signed list;
    //                     all encrypted parts in order they are added to the encrypted list; all parts required.
    //                     In this example, we expect compound beacons to be written as
    //                     `L-XXX.U-YYYYYYYY`, since our encrypted list looks like
    //                     [last4EncryptedPart, unitEncryptedPart].
    //     - signed: A list of signed parts, i.e. plaintext attributes. This would be provided if we
    //                     wanted to use plaintext values as part of constructing our compound beacon. We do not
    //                     provide this here; see the Complex example for an example.
    final CompoundBeacon last4UnitCompoundBeacon = CompoundBeacon
      .builder()
      .name("last4UnitCompound")
      .constructors(constructor)
      .split(".")
      .build();

    // 4. Configure the Keystore
    //    These are the same constructions as in the Basic example, which describes these in more detail.
    final BranchKeyStore keyStore = BranchKeyStore
      .builder()
      .kmsClient(KmsClient.create())
      .ddbClient(DynamoDbClient.create())
      .ddbTableName(keyStoreTableName)
      .logicalKeyStoreName(keyStoreTableName)
      .kmsConfiguration(KmsConfiguration.kmsKeyArn(branchKeyWrappingKmsKeyArn))
      .build();

    // 5. Create BeaconConfig.
    //    This is similar to the Basic example, except we have also provided a compound beacon.
    //    We must also continue to provide all of the standard beacons that compose a compound beacon.
    final BeaconConfig beaconConfig = BeaconConfig
      .builder()
      .encryptedParts(last4EncryptedPart, unitEncryptedPart)
      .standardBeacons(last4Beacon, unitBeacon)
      .compoundBeacons(last4UnitCompoundBeacon)
      .keyStore(keyStore)
      .keySource(
        BeaconKeySource
          .singleBeaconKey(branchKeyId)
          .cacheTtl(Duration.ofSeconds(6000))
          .build()
      )
      .build();

    // 6. Create a Hierarchical Keyring
    //    This is the same configuration as in the Basic example.
    final Keyring kmsKeyring = AwsKmsHierarchicalKeyring
      .builder()
      .branchKeyId(branchKeyId)
      .keyStore(keyStore)
      .ttl(Duration.ofSeconds(6000))
      .build();

    // 7. Decide how each attribute of your items is protected. Give each attribute one of these
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
      .encryptAndSign("inspector_id_last4", "unit")
      .build();

    // We do not need to define a crypto action on last4UnitCompound.
    // We only need to define crypto actions on attributes that we pass to PutItem.

    // 8. Create the DynamoDB Encryption configuration for the table we will be writing to.
    //    The beacon configuration is added to the table configuration.
    final DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .logicalTableName(tableName)
      .schema(schema)
      .keyring(kmsKeyring)
      .beaconConfig(beaconConfig)
      .build();

    // 9. Create an item with both attributes used in the compound beacon.
    final Map<String, AttributeValue> item = new HashMap<>();
    item.put(
      "work_id",
      AttributeValue
        .builder()
        .s("9ce39272-8068-4efd-a211-cd162ad65d4c")
        .build()
    );
    item.put(
      "inspection_date",
      AttributeValue.builder().s("2023-06-13").build()
    );
    item.put("inspector_id_last4", AttributeValue.builder().s("5678").build());
    item.put("unit", AttributeValue.builder().s("011899988199").build());
    final DynamoDbEncryptionTransforms transformClient = DynamoDbEncryptionTransforms
      .builder()
      .tableConfigs(config)
      .build();

    // VirtualFields is empty because we have no Virtual Fields configured
    assert transformClient.resolveVirtualFields(tableName, item).isEmpty();

    // Verify that CompoundBeacons has the expected value
    final Map<String, String> expectedCompoundBeacons = new HashMap<>();
    expectedCompoundBeacons.put("last4UnitCompound", "L-5678.U-011899988199");
    assert transformClient
      .resolveCompoundBeacons(tableName, item)
      .equals(expectedCompoundBeacons);
    // Note : the compound beacon actually stored in the table is not "L-5678.U-011899988199"
    // but rather something like "L-abc.U-123", as both parts are EncryptedParts
    // and therefore the text is replaced by the associated beacon

    // 11. Create the DynamoDB Encryption Interceptor
    final DynamoDbEncryptionInterceptor encryptionInterceptor =
      DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();

    // 12. Create a new AWS SDK DynamoDB client using the DynamoDB Encryption Interceptor above
    try (
      DynamoDbClient dynamoDbClient = DynamoDbClient
        .builder()
        .overrideConfiguration(overrides ->
          overrides.addExecutionInterceptor(encryptionInterceptor)
        )
        .build()
    ) {
      putAndQueryItemWithClient(dynamoDbClient, tableName, item);

      // If instead you were working in a multi-threaded context
      // it might look like this: each task writes and queries the item
      // PUT_AND_QUERY_ROUNDS_PER_TASK times, and TASK_COUNT tasks share a pool
      // of MAX_CONCURRENT_QUERY_THREADS threads.
      final Runnable putAndQueryTask = () -> {
        for (int round = 0; round < PUT_AND_QUERY_ROUNDS_PER_TASK; round++) {
          putAndQueryItemWithClient(dynamoDbClient, tableName, item);
        }
      };
      final ExecutorService executor = Executors.newFixedThreadPool(
        MAX_CONCURRENT_QUERY_THREADS
      );
      Collections.nCopies(TASK_COUNT, putAndQueryTask).forEach(executor::execute);
      executor.shutdown();
      try {
        executor.awaitTermination(30, TimeUnit.SECONDS);
      } catch (InterruptedException exception) {
        Thread.currentThread().interrupt();
      }
    }
  }

  public static void putAndQueryItemWithClient(
    DynamoDbClient dynamoDbClient,
    String tableName,
    Map<String, AttributeValue> item
  ) {
    // 13. Write the item to the table
    final PutItemRequest putRequest = PutItemRequest
      .builder()
      .tableName(tableName)
      .item(item)
      .build();

    dynamoDbClient.putItem(putRequest);

    // 14. Query for the item we just put.
    final Map<String, String> expressionAttributeNames = new HashMap<>();
    expressionAttributeNames.put("#compound", "last4UnitCompound");
    final Map<String, AttributeValue> expressionAttributeValues =
      new HashMap<>();
    // This query expression takes a few factors into consideration:
    //  - The configured prefix for the last 4 digits of an inspector ID is "L-";
    //    the prefix for the unit is "U-"
    //  - The configured split character, separating component parts, is "."
    //  - The default constructor adds encrypted parts in the order they are in the encrypted list, which
    //    configures `last4` to come before `unit``
    // NOTE: We did not need to create a compound beacon for this query. This query could have also been
    //       done by querying on the partition and sort key, as was done in the Basic example.
    //       This is intended to be a simple example to demonstrate how one might set up a compound beacon.
    //       For examples where compound beacons are required, see the Complex example.
    //       The most basic extension to this example that would require a compound beacon would add a third
    //       part to the compound beacon, then query against three parts.
    expressionAttributeValues.put(
      ":value",
      AttributeValue.builder().s("L-5678.U-011899988199").build()
    );

    final QueryRequest queryRequest = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName(GSI_NAME)
      .keyConditionExpression("#compound = :value")
      .expressionAttributeNames(expressionAttributeNames)
      .expressionAttributeValues(expressionAttributeValues)
      .build();

    // GSIs do not update instantly
    // so if the results come back empty
    // we retry after a short sleep
    final int maxQueryAttempts = 10;
    final Duration pollInterval = Duration.ofMillis(20);
    for (int attempt = 0; attempt < maxQueryAttempts; attempt++) {
      final List<Map<String, AttributeValue>> attributeValues = dynamoDbClient
        .query(queryRequest)
        .items();

      // if no results, sleep and try again
      if (attributeValues.isEmpty()) {
        try {
          Thread.sleep(pollInterval.toMillis());
        } catch (InterruptedException exception) {
          Thread.currentThread().interrupt();
          break;
        }
        continue;
      }

      // Validate only 1 item was returned: the item we just put
      assert attributeValues.size() == 1;
      final Map<String, AttributeValue> returnedItem = attributeValues.get(0);
      // Validate the item has the expected attributes
      assert returnedItem.get("inspector_id_last4").s().equals("5678");
      assert returnedItem.get("unit").s().equals("011899988199");
      break;
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
    putAndQueryItem(
      tableName,
      branchKeyId,
      branchKeyWrappingKmsKeyArn,
      keyStoreTableName
    );
  }
}
