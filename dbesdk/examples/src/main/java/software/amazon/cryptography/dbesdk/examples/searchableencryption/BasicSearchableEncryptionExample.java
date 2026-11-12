package software.amazon.cryptography.dbesdk.examples.searchableencryption;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconKeySource;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.StandardBeacon;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.transforms.DynamoDbEncryptionTransforms;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;

/**
 * This example demonstrates how to set up a beacon on an encrypted attribute, put an item with the
 * beacon, and query against that beacon. This example follows a use case of a database that stores
 * unit inspection information.
 *
 * <p>Running this example requires access to a DynamoDB table with the following key configuration:
 *   - Partition key is named "work_id" with type (S)
 *   - Sort key is named "inspection_date" with type (S)
 * This table must have a Global Secondary Index (GSI) configured named "last4-unit-index":
 *   - Partition key is named "aws_dbe_b_inspector_id_last4" with type (S)
 *   - Sort key is named "aws_dbe_b_unit" with type (S)
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
 *   4. Branch key DynamoDB table name for the DynamoDB table representing the branch key store
 */
public class BasicSearchableEncryptionExample {

  private static final String GSI_NAME = "last4-unit-index";

  public static void putAndQueryItem(
    String tableName,
    String branchKeyId,
    String branchKeyWrappingKmsKeyArn,
    String keyStoreTableName
  ) {
    // 1. Configure Beacons.
    //    The beacon name must be the name of a table attribute that will be encrypted.
    //    The `bitLength` setting dictates how many bits are in the beacon attribute value.
    //    The following link provides guidance on choosing a beacon length:
    //        https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/choosing-beacon-length.html

    // The configured DynamoDB table has a GSI on the `aws_dbe_b_inspector_id_last4` AttributeName.
    // This field holds the last 4 digits of an inspector ID.
    // For our example, this field may range from 0 to 9,999 (10,000 possible values).
    // For our example, we assume a full inspector ID is an integer
    //     ranging from 0 to 99,999,999. We do not assume that the full inspector ID's
    //     values are uniformly distributed across its range of possible values.
    //     In many use cases, the prefix of an identifier encodes some information
    //     about that identifier (e.g. zipcode and SSN prefixes encode geographic
    //     information), while the suffix does not encode such structure and tends
    //     to be closer to uniformly distributed, though not perfectly uniform.
    //     We will assume that the inspector ID field matches a similar use case.
    //     For this example, we use only the last four digits of the inspector ID and apply one partitions,
    //     assuming the suffix has sufficient uniformity for this purpose.
    // Since the full ID's range is divisible by the range of the last 4 digits,
    //     then the last 4 digits of the inspector ID are uniformly distributed
    //     over the range from 0 to 9,999.
    // See our documentation for why you should avoid creating beacons over non-uniform distributions
    //  https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/searchable-encryption.html#are-beacons-right-for-me
    // A single inspector ID suffix may be assigned to multiple `work_id`s.
    //
    // This link provides guidance for choosing a beacon length:
    //    https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/choosing-beacon-length.html
    // We follow the guidance in the link above to determine reasonable bounds
    // for the length of a beacon on the last 4 digits of an inspector ID:
    //  - min: log(sqrt(10,000))/log(2) ~= 6.6, round up to 7
    //  - max: log((10,000/2))/log(2) ~= 12.3, round down to 12
    // You will somehow need to round results to a nearby integer.
    // We choose to round to the nearest integer; you might consider a different rounding approach.
    // Rounding up will return fewer expected "false positives" in queries,
    //    leading to fewer decrypt calls and better performance,
    //    but it is easier to identify which beacon values encode distinct plaintexts.
    // Rounding down will return more expected "false positives" in queries,
    //    leading to more decrypt calls and worse performance,
    //    but it is harder to identify which beacon values encode distinct plaintexts.
    // We can choose a beacon length between 7 and 12:
    //  - Closer to 7, we expect more "false positives" to be returned,
    //    making it harder to identify which beacon values encode distinct plaintexts,
    //    but leading to more decrypt calls and worse performance
    //  - Closer to 12, we expect fewer "false positives" returned in queries,
    //    leading to fewer decrypt calls and better performance,
    //    but it is easier to identify which beacon values encode distinct plaintexts.
    // As an example, we will choose 10.
    //
    // Values stored in aws_dbe_b_inspector_id_last4 will be 10 bits long (0x000 - 0x3ff)
    // There will be 2^10 = 1,024 possible HMAC values.
    // With a sufficiently large number of well-distributed inspector IDs,
    //    for a particular beacon we expect (10,000/1,024) ~= 9.8 4-digit inspector ID suffixes
    //    sharing that beacon value.
    StandardBeacon last4Beacon = StandardBeacon
      .builder()
      .name("inspector_id_last4")
      .bitLength(10)
      .numberOfPartitions(1)
      .build();

    // The configured DynamoDB table has a GSI on the `aws_dbe_b_unit` AttributeName.
    // This field holds a unit serial number.
    // For this example, this is a 12-digit integer from 0 to 999,999,999,999 (10^12 possible values).
    // We will assume values for this attribute are uniformly distributed across this range using 1 partition.
    // A single unit serial number may be assigned to multiple `work_id`s.
    //
    // This link provides guidance for choosing a beacon length:
    //    https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/choosing-beacon-length.html
    // We follow the guidance in the link above to determine reasonable bounds
    // for the length of a beacon on a unit serial number:
    //  - min: log(sqrt(999,999,999,999))/log(2) ~= 19.9, round up to 20
    //  - max: log((999,999,999,999/2))/log(2) ~= 38.9, round up to 39
    // We can choose a beacon length between 20 and 39:
    //  - Closer to 20, we expect more "false positives" to be returned,
    //    making it harder to identify which beacon values encode distinct plaintexts,
    //    but leading to more decrypt calls and worse performance
    //  - Closer to 39, we expect fewer "false positives" returned in queries,
    //    leading to fewer decrypt calls and better performance,
    //    but it is easier to identify which beacon values encode distinct plaintexts.
    // As an example, we will choose 30.
    //
    // Values stored in aws_dbe_b_unit will be 30 bits long (0x00000000 - 0x3fffffff)
    // There will be 2^30 = 1,073,741,824 ~= 1.1B possible HMAC values.
    // With a sufficiently large number of well-distributed unit serial numbers,
    //    for a particular beacon we expect (10^12/2^30) ~= 931.3 unit serial numbers
    //    sharing that beacon value.
    StandardBeacon unitBeacon = StandardBeacon
      .builder()
      .name("unit")
      .bitLength(30)
      .numberOfPartitions(1)
      .build();

    // 2. Configure Keystore. The keystore is a separate DynamoDB table where the client stores
    //    encryption and decryption materials. In order to configure beacons on the DynamoDB client,
    //    you must configure a keystore.
    //
    //    This example expects that you have already set up a KeyStore with a single branch key.
    //    See the "Create KeyStore Table Example" and "Create KeyStore Key Example" for how to do this.
    //    After you create a branch key, you should persist its ID for use in this example.
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

      // 3. Create BeaconConfig. The BeaconConfig holds the list of beacons on the table. The
      //    BeaconConfig also stores information about the keystore. The BeaconConfig parameter
      //    specifies the maximumNumberOfPartitions associated with a given beacon configuration.
      //    "maximumNumberOfPartitions" must be greater than "numberOfPartitions"; we set it to 2 to
      //    allow room for future expansion. BeaconConfig must be provided:
      //      - keyStore: The keystore configured in step 2.
      //      - keySource: A configuration for the key source.
      //        For simple use cases, use BeaconKeySource.singleBeaconKey, which uses one beacon
      //        key for every item. That is the approach this example takes.
      //        For use cases where you want to use different beacon keys depending on the data
      //        (for example if your table holds data for multiple tenants, and you want to use
      //        a different beacon key per tenant), use BeaconKeySource.multipleBeaconKeys:
      //          https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/searchable-encryption-multitenant.html
      BeaconConfig beaconConfig = BeaconConfig
        .builder()
        .standardBeacons(last4Beacon, unitBeacon)
        .maximumNumberOfPartitions(2)
        // A beacon that does not set numberOfPartitions uses defaultNumberOfPartitions, and that
        // defaults to maximumNumberOfPartitions. That is why each beacon above sets
        // numberOfPartitions(1). To change the default instead, set defaultNumberOfPartitions,
        // which must be greater than 0 and less than maximumNumberOfPartitions.
        .keyStore(keyStore)
        .keySource(
          // The argument is a beacon key ID.
          // For every branch key we create in the keystore,
          // we also create a beacon key.
          // This beacon key is not the same as the branch key,
          // but is created with the same ID as the branch key.
          BeaconKeySource
            .singleBeaconKey(branchKeyId)
            .cacheTtl(Duration.ofSeconds(6000))
            .build()
        )
        .build();

      // 4. Create a Hierarchical Keyring
      //    This is a KMS keyring that utilizes the keystore table.
      //    This config defines how items are encrypted and decrypted.
      //    Give it the same keystore as the beacon configuration. The beacon key this example
      //    uses has the same ID as the branch key, and both are stored in that keystore.
      Keyring kmsKeyring = AwsKmsHierarchicalKeyring
        .builder()
        .branchKeyId(branchKeyId)
        .keyStore(keyStore)
        .ttl(Duration.ofSeconds(6000))
        .build();

      // 5. Decide how each attribute of your items is protected. BasicPutGetExample
      //    explains each action (encryptAndSign, signOnly, signAndIncludeInEncryptionContext,
      //    doNothing), and why the partition and sort keys get none.
      //    Attributes used in beacons must use encryptAndSign.
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

      // 6. Create the DynamoDB Encryption configuration for the table we will be writing to.
      //    The beacon configuration is added to the table configuration.
      DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
        .builder()
        .tableName(tableName)
        .logicalTableName(tableName)
        .schema(schema)
        .keyring(kmsKeyring)
        .beaconConfig(beaconConfig)
        .build();

      // 7. Create the DynamoDB Encryption Interceptor
      DynamoDbEncryptionInterceptor encryptionInterceptor =
        DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();

      // 8. Create a new AWS SDK DynamoDB client using the DynamoDB Encryption Interceptor above
      try (
        DynamoDbClient dynamoDbClient = DynamoDbClient
          .builder()
          .overrideConfiguration(overrides ->
            overrides.addExecutionInterceptor(encryptionInterceptor)
          )
          .build()
      ) {
        // 9. Put an item into our table using the above client.
        //    Before the item gets sent to DynamoDB, it will be encrypted
        //        client-side, according to our configuration.
        //    Since our configuration includes beacons for `inspector_id_last4` and `unit`,
        //        the client will add two additional attributes to the item. These attributes will have names
        //        `aws_dbe_b_inspector_id_last4` and `aws_dbe_b_unit`. Their values will be HMACs
        //        truncated to as many bits as the beacon's `bitLength` setting; e.g.
        //    aws_dbe_b_inspector_id_last4 = truncate(HMAC("4321"), 10)
        //    aws_dbe_b_unit = truncate(HMAC("123456789012"), 30)
        Map<String, AttributeValue> item = Map.of(
          "work_id",
          AttributeValue.fromS("1313ba89-5661-41eb-ba6c-cb1b4cb67b2d"),
          "inspection_date",
          AttributeValue.fromS("2023-06-13"),
          "inspector_id_last4",
          AttributeValue.fromS("4321"),
          "unit",
          AttributeValue.fromS("123456789012")
        );
        PutItemRequest putRequest = PutItemRequest
          .builder()
          .tableName(tableName)
          .item(item)
          .build();

        dynamoDbClient.putItem(putRequest);

        // 10. Query for the item we just put.
        //     Note that we are constructing the query as if we were querying on plaintext values.
        //     However, the DynamoDB encryption client will detect that this attribute name has a
        //     beacon configured. The client will add the beaconized attribute name and attribute
        //     value to the query, and transform the query to use the beaconized name and value.
        //     Internally, the client will query for and receive all items with a matching HMAC
        //     value in the beacon field. This may include a number of "false positives" with
        //     different ciphertext, but the same truncated HMAC.
        //     e.g. if truncate(HMAC("123456789012"), 30)
        //          == truncate(HMAC("098765432109"), 30),
        //     the query will return both items.
        //     The client will decrypt all returned items to determine which ones have the expected
        //     attribute values, and only surface items with the correct plaintext to the user.
        //     This procedure is internal to the client and is abstracted away from the user;
        //     e.g. the user will only see "123456789012" and never
        //        "098765432109", though the actual query returned both.

        List<Map<String, AttributeValue>> allResults = new ArrayList<>();

        Map<String, String> expressionAttributeNames = Map.of(
          "#last4",
          "inspector_id_last4",
          "#unit",
          "unit"
        );
        Map<String, AttributeValue> expressionAttributeValues = Map.of(
          ":last4",
          AttributeValue.fromS("4321"),
          ":unit",
          AttributeValue.fromS("123456789012")
        );

        QueryRequest queryRequest = QueryRequest
          .builder()
          .tableName(tableName)
          .indexName(GSI_NAME)
          .keyConditionExpression("#last4 = :last4 and #unit = :unit")
          .expressionAttributeNames(expressionAttributeNames)
          .expressionAttributeValues(expressionAttributeValues)
          .build();

        DynamoDbEncryptionTransforms transformClient =
          DynamoDbEncryptionTransforms.builder().tableConfigs(config).build();

        // A beacon can be split across several partitions, and a query on it then has to be sent
        // once for each partition. partitionQueries builds one request per partition, with the
        // partition number already filled in; it does not call DynamoDB itself. The beacons in this
        // example use one partition each, so there is exactly one request.
        List<QueryRequest> partitionQueries = transformClient.partitionQueries(
          queryRequest
        );

        // Send every request through the encrypting client and collect the results.
        // GSIs do not update instantly, so if a partition's query comes back empty,
        // wait briefly and query that partition again.
        int maxQueryAttempts = 10;
        Duration pollInterval = Duration.ofMillis(20);
        for (QueryRequest partitionQuery : partitionQueries) {
          for (int attempt = 0; attempt < maxQueryAttempts; attempt++) {
            List<Map<String, AttributeValue>> partitionResults = dynamoDbClient
              .query(partitionQuery)
              .items();
            if (!partitionResults.isEmpty()) {
              // Adding the result for this partition
              allResults.addAll(partitionResults);
              break;
            }
            try {
              Thread.sleep(pollInterval.toMillis());
            } catch (InterruptedException exception) {
              Thread.currentThread().interrupt();
              break;
            }
          }
        }

        // Validate only 1 item was returned: the item we just put
        assert allResults.size() == 1;
        Map<String, AttributeValue> returnedItem = allResults.get(0);
        // Validate the item has the expected attributes
        assert returnedItem.get("inspector_id_last4").s().equals("4321");
        assert returnedItem.get("unit").s().equals("123456789012");
      }
    }
  }

  public static void main(String[] args) {
    if (args.length < 4) {
      throw new IllegalArgumentException(
        "To run this example, include tableName as args[0], " +
        "branchKeyId as args[1], branchKeyWrappingKmsKeyArn as args[2], and keyStoreTableName as args[3]"
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
