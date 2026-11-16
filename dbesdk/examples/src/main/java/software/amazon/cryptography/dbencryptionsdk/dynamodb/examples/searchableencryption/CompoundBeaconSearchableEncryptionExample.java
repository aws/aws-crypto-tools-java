package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.searchableencryption;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconKeySource;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconStyle;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.CompoundBeacon;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.CompoundBeaconConstructor;
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

/**
 * This example demonstrates how to set up a compound beacon on encrypted attributes, put an item with
 * the beacon, and query against that beacon. This example follows a use case of a database that
 * stores unit inspection information. This is an extension of the "BasicSearchableEncryptionExample"
 * in this directory. This example uses the same situation (storing unit inspection information) and
 * the same table schema. However, this example uses a different Global Secondary Index (GSI) that is
 * based on a compound beacon configuration composed of the `last4` and `unit` attributes.
 *
 * <p>Running this example requires access to a DynamoDB table with the following key configuration:
 *   - Partition key is named "work_id" with type (S)
 *   - Sort key is named "inspection_date" with type (S)
 * This table must have a Global Secondary Index (GSI) configured named "last4UnitCompound-index":
 *   - Partition key is named "aws_dbe_b_last4UnitCompound" with type (S)
 *
 * <p>In this example for storing unit inspection information, this schema is utilized for the data:
 *  - "work_id" stores a unique identifier for a unit inspection work order (v4 UUID)
 *  - "inspection_date" stores an ISO 8601 date for the inspection (YYYY-MM-DD)
 *  - "inspector_id_last4" stores the last 4 digits of the ID of the inspector performing the work
 *  - "unit" stores a 12-digit serial number for the unit being inspected
 *
 * <p>The example requires the following ordered input command line parameters:
 *   1. DynamoDB table name for table to put/query data from
 *   2. Branch key ID for a branch key that was previously created in your key store. See the
 *      CreateKeyStoreKeyExample.
 *   3. Branch key wrapping KMS key ARN for the KMS key used to create the branch key with ID
 *      provided in arg 2
 *   4. Branch key DynamoDB table ARN for the DynamoDB table representing the branch key store
 */
public class CompoundBeaconSearchableEncryptionExample {

  private static final String GSI_NAME = "last4UnitCompound-index";
  private static final int CONCURRENT_TASK_COUNT = 2;

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
    //    We give them both the partOnly style to enforce the fact that
    //      we will not directly query against these beacons.
    StandardBeacon last4Beacon = StandardBeacon
      .builder()
      .name("inspector_id_last4")
      .bitLength(10)
      .style(BeaconStyle.partOnly())
      .build();
    StandardBeacon unitBeacon = StandardBeacon
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
    //            Prefixes must be unique across the configuration, and must not be a prefix of
    //            another prefix; i.e. for all configured prefixes, the first N characters of a
    //            prefix must not equal another prefix.
    // In practice, it is suggested to have a short value distinguishable from other parts served on
    // the prefix.

    // For this example, we will choose "L-" as the prefix for "Last 4 digits of inspector ID".
    // With this prefix and the standard beacon's bit length definition (10), the beaconized
    //     version of the inspector ID's last 4 digits will appear as
    //     `L-000` to `L-3ff` inside a compound beacon.
    EncryptedPart last4EncryptedPart = EncryptedPart
      .builder()
      .name("inspector_id_last4")
      .prefix("L-")
      .build();
    // For this example, we will choose "U-" as the prefix for "unit".
    // With this prefix and the standard beacon's bit length definition (30), a unit beacon will appear
    //     as `U-00000000` to `U-3fffffff` inside a compound beacon.
    EncryptedPart unitEncryptedPart = EncryptedPart
      .builder()
      .name("unit")
      .prefix("U-")
      .build();

    // A constructor is one allowed way to assemble the compound beacon's value: an ordered list of
    // parts, joined by the compound beacon's separator. addRequiredPart names parts that must be on
    // the item for this constructor to be used; addOptionalPart names parts that are left out when
    // they are missing. Each takes one or more names, and the parts are written in the order they
    // are given. This constructor writes the beacon as `L-XXX.U-YYYYYYYY` and needs both parts.
    CompoundBeaconConstructor constructor = CompoundBeaconConstructor
      .builder()
      .addRequiredPart("inspector_id_last4", "unit")
      .build();

    // 3. Define compound beacon.
    //    A compound beacon allows one to serve multiple beacons or attributes from a single index.
    //    A compound beacon must receive:
    //     - name: The name of the beacon. Compound beacon values will be written to `aws_dbe_b_[name]`.
    //     - separator: The character written between the parts of a compound beacon value
    //    A compound beacon may also receive:
    //     - constructors: An ordered list of possible ways to build the beacon value. When an item is
    //                     written, the first constructor whose required parts are all on the item is
    //                     used. If you give none, the library uses one constructor made of all signed
    //                     parts, then all encrypted parts, in the order they are listed, all required.
    //                     That default would also write `L-XXX.U-YYYYYYYY` here; the constructor
    //                     above shows how to write one explicitly.
    //    The encrypted parts themselves are listed on the beacon configuration in step 5.
    //     - signed: A list of signed parts, i.e. plaintext attributes. This would be provided if we
    //                     wanted to use plaintext values as part of constructing our compound
    //                     beacon. We do not provide this here; see the Complex example for an
    //                     example.
    CompoundBeacon last4UnitCompoundBeacon = CompoundBeacon
      .builder()
      .name("last4UnitCompound")
      .constructors(constructor)
      .separator('.')
      .build();

    // 4. Configure the Keystore
    //    These are the same constructions as in the Basic example, which describes these in more detail.
    // The DynamoDB and AWS KMS clients the keystore uses. Both are optional: without them, the
    // keystore creates its own in the region of the KMS key ARN. KmsClient.create() and
    // DynamoDbClient.create() use your environment's default region and credentials instead.
    // The try block closes them when it ends, so everything that uses the keystore stays inside it.
    try (
      DynamoDbClient keyStoreDynamoDbClient = DynamoDbClient.create();
      KmsClient keyStoreKmsClient = KmsClient.create()
    ) {
      BranchKeyStore keyStore = BranchKeyStore
        .builder()
        .ddbTableName(keyStoreTableName)
        .logicalKeyStoreName(keyStoreTableName)
        .kmsConfiguration(
          KmsConfiguration.kmsKeyArn(branchKeyWrappingKmsKeyArn)
        )
        .ddbClient(keyStoreDynamoDbClient)
        .kmsClient(keyStoreKmsClient)
        .build();

      // 5. Create BeaconConfig.
      //    This is similar to the Basic example, except we have also provided a compound beacon.
      //    We must also continue to provide all of the standard beacons that compose a compound beacon.
      BeaconConfig beaconConfig = BeaconConfig
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
      Keyring kmsKeyring = AwsKmsHierarchicalKeyring
        .builder()
        .branchKeyId(branchKeyId)
        .keyStore(keyStore)
        .ttl(Duration.ofSeconds(6000))
        .build();

      // 7. Decide how each attribute of your items is protected. BasicPutGetExample
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
        .encryptAndSign("inspector_id_last4", "unit")
        .build();

      // We do not need to define a crypto action on last4UnitCompound.
      // We only need to define crypto actions on attributes that we pass to PutItem.

      // 8. Create the DynamoDB Encryption configuration for the table we will be writing to.
      //    The beacon configuration is added to the table configuration.
      DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
        .builder()
        .tableName(tableName)
        .schema(schema)
        .keyring(kmsKeyring)
        .beaconConfig(beaconConfig)
        .build();

      // 9. Create an item with both attributes used in the compound beacon.
      Map<String, AttributeValue> item = Map.of(
        "work_id",
        AttributeValue.fromS("9ce39272-8068-4efd-a211-cd162ad65d4c"),
        "inspection_date",
        AttributeValue.fromS("2023-06-13"),
        "inspector_id_last4",
        AttributeValue.fromS("5678"),
        "unit",
        AttributeValue.fromS("011899988199")
      );
      DynamoDbEncryptionTransforms transformClient =
        DynamoDbEncryptionTransforms.builder().tableConfigs(config).build();

      // resolveVirtualFields returns an empty map because no virtual fields are configured
      assert transformClient.resolveVirtualFields(tableName, item).isEmpty();

      // Verify that resolveCompoundBeacons returns the expected value
      Map<String, String> expectedCompoundBeacons = Map.of(
        "last4UnitCompound",
        "L-5678.U-011899988199"
      );
      assert transformClient
        .resolveCompoundBeacons(tableName, item)
        .equals(expectedCompoundBeacons);
      // Note : the compound beacon actually stored in the table is not "L-5678.U-011899988199"
      // but rather something like "L-abc.U-123", as both parts are encrypted parts
      // and therefore the text is replaced by the associated beacon

      // 10. Create the DynamoDB Encryption Interceptor
      DynamoDbEncryptionInterceptor encryptionInterceptor =
        DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();

      // 11. Create a new AWS SDK DynamoDB client using the DynamoDB Encryption Interceptor above
      try (
        DynamoDbClient dynamoDbClient = DynamoDbClient
          .builder()
          .overrideConfiguration(overrides ->
            overrides.addExecutionInterceptor(encryptionInterceptor)
          )
          .build()
      ) {
        putAndQueryItemWithClient(dynamoDbClient, tableName, item);

        // If instead you were working in a multi-threaded context, you can share this one client
        // across threads. Here CONCURRENT_TASK_COUNT tasks each write and query the item at the
        // same time, on their own threads.
        Callable<Object> putAndQueryTask = Executors.callable(() ->
          putAndQueryItemWithClient(dynamoDbClient, tableName, item)
        );
        ExecutorService executor = Executors.newFixedThreadPool(
          CONCURRENT_TASK_COUNT
        );
        try {
          // invokeAll returns only after every task has finished, so the client is not closed
          // while a task is still using it.
          List<Future<Object>> results = executor.invokeAll(
            Collections.nCopies(CONCURRENT_TASK_COUNT, putAndQueryTask)
          );
          // A task's exception is held in its Future. get() rethrows it, so a failed write or
          // query in any task fails this example.
          for (Future<Object> result : results) {
            result.get();
          }
        } catch (InterruptedException exception) {
          Thread.currentThread().interrupt();
        } catch (ExecutionException exception) {
          throw new IllegalStateException(
            "A concurrent put-and-query task failed",
            exception.getCause()
          );
        } finally {
          executor.shutdown();
        }
      }
    }
  }

  private static void putAndQueryItemWithClient(
    DynamoDbClient dynamoDbClient,
    String tableName,
    Map<String, AttributeValue> item
  ) {
    // 12. Write the item to the table
    PutItemRequest putRequest = PutItemRequest
      .builder()
      .tableName(tableName)
      .item(item)
      .build();

    dynamoDbClient.putItem(putRequest);

    // 13. Query for the item we just put.
    Map<String, String> expressionAttributeNames = Map.of(
      "#compound",
      "last4UnitCompound"
    );
    Map<String, AttributeValue> expressionAttributeValues = Map.of(
      // This query expression takes a few factors into consideration:
      //  - The configured prefix for the last 4 digits of an inspector ID is "L-";
      //    the prefix for the unit is "U-"
      //  - The configured separator, written between the parts, is "."
      //  - The constructor lists `inspector_id_last4` before `unit`, so the last 4 digits come
      //    first
      // NOTE: We did not need to create a compound beacon for this query. This query could have also been
      //       done by querying on the partition and sort key, as was done in the Basic example.
      //       This is intended to be a simple example to demonstrate how one might set up a compound beacon.
      //       For examples where compound beacons are required, see the Complex example.
      //       The most basic extension to this example that would require a compound beacon would add a third
      //       part to the compound beacon, then query against three parts.
      ":value",
      AttributeValue.fromS("L-5678.U-011899988199")
    );

    QueryRequest queryRequest = QueryRequest
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
    int maxQueryAttempts = 10;
    Duration pollInterval = Duration.ofMillis(20);
    List<Map<String, AttributeValue>> attributeValues = List.of();
    for (int attempt = 0; attempt < maxQueryAttempts; attempt++) {
      attributeValues = dynamoDbClient.query(queryRequest).items();
      if (!attributeValues.isEmpty()) {
        break;
      }
      try {
        Thread.sleep(pollInterval.toMillis());
      } catch (InterruptedException exception) {
        Thread.currentThread().interrupt();
        break;
      }
    }

    // Validate only 1 item was returned: the item we just put. This also fails if every
    // attempt came back empty.
    assert attributeValues.size() == 1;
    Map<String, AttributeValue> returnedItem = attributeValues.get(0);
    // Validate the item has the expected attributes
    assert returnedItem.get("inspector_id_last4").s().equals("5678");
    assert returnedItem.get("unit").s().equals("011899988199");
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
    putAndQueryItem(
      tableName,
      branchKeyId,
      branchKeyWrappingKmsKeyArn,
      keyStoreTableName
    );
  }
}
