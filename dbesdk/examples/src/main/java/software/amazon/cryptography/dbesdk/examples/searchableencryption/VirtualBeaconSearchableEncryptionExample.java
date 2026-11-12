package software.amazon.cryptography.dbesdk.examples.searchableencryption;

import java.time.Duration;
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
import software.amazon.cryptography.dbencryptionsdk.dynamodb.VirtualField;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.VirtualPart;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.VirtualTransform;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.transforms.DynamoDbEncryptionTransforms;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;

/**
 * This example demonstrates how to set up a virtual field from two DynamoDB attributes, create a standard
 * beacon with that field, put an item with that beacon, and query against that beacon.
 *
 * <p>A virtual field is a field consisting of a transformation of one or more attributes in a DynamoDB item.
 * Virtual fields are useful in querying against encrypted fields that only have a handful of possible
 * values. They allow you to take fields with few possible values, concatenate them to other fields,
 * then query against the combined field. This enables using these types of fields in queries while
 * making it infeasible to identify which beacon values encode the few possible distinct plaintexts.
 * This is explained in more detail below. Virtual fields are not stored in the DynamoDB table. However,
 * they are used to construct a beacon, the value of which is stored.
 *
 * <p>For more information on virtual fields, see
 *   https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/beacons.html#virtual-field
 *
 * <p>For our example, we will construct a virtual field from two DynamoDB attributes `state` and
 * `hasTestResult` as `state`+prefix(`hasTestResult`, 1). We will then create a beacon out of this
 * virtual field and use it to search.
 *
 * <p>This example follows a use case of a database that stores customer test result metadata. Records
 * are indexed by `customer_id` and store a `state` attribute, representing the US state or territory
 * where the customer lives, and a `hasTestResult` boolean attribute, representing whether the
 * customer has a "test result" available. (Maybe this represents some medical test result, and this
 * table stores "result available" metadata.) We assume that values in these fields are uniformly
 * distributed across all possible values for these fields (56 for `state`, 2 for `hasTestResult`),
 * and are uniformly distributed across customer IDs.
 *
 * <p>The motivation behind this example is to demonstrate how and why one would use a virtual beacon. In
 * this example, our table stores records with an encrypted boolean `hasTestResult` attribute. We
 * would like to be able to query for customers in a given state with a `true` hasTestResult
 * attribute.
 *
 * <p>To be able to execute this query securely and efficiently, we want the following properties on our
 * table:
 *  1. Hide the distribution of `hasTestResult` attribute values (i.e. it should be infeasible
 *     to determine the percentage of `true`s to `false`s across the dataset from beaconized values)
 *  2. Query against a combination of whether `hasTestResult` is true/false and the `state` field
 * We cannot achieve these properties with a standard beacon on a true/false attribute. Following the
 * guidance to choose a beacon length:
 *   https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/choosing-beacon-length.html
 * For a boolean value (in our case, whether `hasTestResult` is true or false), the acceptable bounds
 * for beacon length are either 0 or 1. This corresponds to either not storing a beacon (length 0), or
 * effectively storing another boolean attribute (length 1). With length 0, this beacon is useless for
 * searching (violating property 2); with length 1, this beacon may not hide the attribute (violating
 * property 1). In addition, choosing a longer beacon length does not help us. Each attribute value is
 * mapped to a distinct beacon. Since booleans only have 2 possible attribute values, we will still
 * only have 2 possible beacon values, though those values may be longer. A longer beacon provides no
 * advantages over beacon of length 1 in this situation.
 *
 * <p>A compound beacon also does not help. To (over)simplify, a compound beacon is a concatenation of
 * standard beacons, i.e. beacon(`state`)+beacon(`hasTestResult`). The `hasTestResult` beacon is still
 * visible, so we would still have the problems above.
 *
 * <p>To achieve these properties, we instead construct a virtual field and use that in our beacon, i.e.
 * beacon(`state`+`hasTestResult`). Assuming these fields are well-distributed across customer IDs and
 * possible values, this gives us both desired properties; we can query against both attributes while
 * hiding information from the underlying data. This is demonstrated in more detail below.
 *
 * <p>Running this example requires access to a DynamoDB table with the following primary key configuration:
 *   - Partition key is named "customer_id" with type (S)
 *   - Sort key is named "create_time" with type (N)
 * This table must have a Global Secondary Index (GSI) configured named "stateAndHasTestResult-index":
 *   - Partition key is named "aws_dbe_b_stateAndHasTestResult" with type (S)
 *
 * <p>In this example for storing customer location data, this schema is utilized for the data:
 *  - "customer_id" stores a unique customer identifier
 *  - "create_time" stores a Unix timestamp
 *  - "state" stores an encrypted 2-letter US state or territory abbreviation
 *        (https://www.faa.gov/air_traffic/publications/atpubs/cnt_html/appendix_a.html)
 *  - "hasTestResult" is not part of the schema, but is an attribute utilized in this example.
 *    It stores a boolean attribute (false/true) indicating whether this customer has a test result
 *    available.
 *
 * <p>The example requires the following ordered input command line parameters:
 *   1. DynamoDB table name for table to put/query data from
 *   2. Branch key ID for a branch key that was previously created in your key store. See the
 *      CreateKeyStoreKeyExample.
 *   3. Branch key wrapping KMS key ARN for the KMS key used to create the branch key
 *   4. Branch key DynamoDB table name for the DynamoDB table representing the branch key store
 */
public class VirtualBeaconSearchableEncryptionExample {

  private static final String GSI_NAME = "stateAndHasTestResult-index";

  public static void putAndQueryItems(
    String tableName,
    String branchKeyId,
    String branchKeyWrappingKmsKeyArn,
    String keyStoreTableName
  ) {
    // 1. Construct a length-1 prefix virtual transform.
    //    `hasTestResult` is a binary attribute, containing either `true` or `false`.
    //    As an example to demonstrate virtual transforms, we will truncate the value
    //    of `hasTestResult` in the virtual field to the length-1 prefix of the binary value, i.e.:
    //     - "true" -> "t"
    //     - "false -> "f"
    //    This is not necessary. This is done as a demonstration of virtual transforms.
    //    Virtual transform operations treat all attributes as strings
    //    (i.e. the boolean value `true` is interpreted as a string "true"),
    //    so its length-1 prefix is just "t".
    VirtualTransform length1PrefixVirtualTransform = VirtualTransform.prefix(1);

    // 2. Construct the VirtualParts required for the VirtualField
    VirtualPart hasTestResultPart = VirtualPart
      .builder()
      .location("hasTestResult")
      // Here, we apply the length-1 prefix virtual transform
      .transforms(length1PrefixVirtualTransform)
      .build();
    VirtualPart statePart = VirtualPart
      .builder()
      .location("state")
      // Note that we do not apply any transform to the `state` attribute,
      // and the virtual field will read in the attribute as-is.
      .build();

    // 3. Construct the VirtualField from the VirtualParts
    //    Note that the order in which virtual parts are passed to parts(...)
    //    dictates the order in which they are concatenated to build the virtual field.
    //    You must pass the virtual parts in the same order on write as you do on read.
    VirtualField stateAndHasTestResultField = VirtualField
      .builder()
      .name("stateAndHasTestResult")
      .parts(statePart, hasTestResultPart)
      .build();

    // 4. Configure our beacon.
    //    The virtual field is assumed to hold a US 2-letter state abbreviation
    //    (56 possible values = 50 states + 6 territories) concatenated with a binary attribute
    //    (2 possible values: true/false hasTestResult field), we expect a population size of
    //    56 * 2 = 112 possible values.
    //    We will also assume that these values are reasonably well-distributed across
    //    customer IDs. In practice, this will not be true. We would expect
    //    more populous states to appear more frequently in the database.
    //    A more complex analysis would show that a stricter upper bound
    //    is necessary to account for this by hiding information from the
    //    underlying distribution.
    //
    //    This link provides guidance for choosing a beacon length:
    //       https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/choosing-beacon-length.html
    //    We follow the guidance in the link above to determine reasonable bounds for beacon length:
    //     - min: log(sqrt(112))/log(2) ~= 3.4, round down to 3
    //     - max: log((112/2))/log(2) ~= 5.8, round up to 6
    //    You will somehow need to round results to a nearby integer.
    //    We choose to round to the nearest integer; you might consider a different rounding approach.
    //    Rounding up will return fewer expected "false positives" in queries,
    //       leading to fewer decrypt calls and better performance,
    //       but it is easier to identify which beacon values encode distinct plaintexts.
    //    Rounding down will return more expected "false positives" in queries,
    //       leading to more decrypt calls and worse performance,
    //       but it is harder to identify which beacon values encode distinct plaintexts.
    //    We can choose a beacon length between 3 and 6:
    //     - Closer to 3, we expect more "false positives" to be returned,
    //       making it harder to identify which beacon values encode distinct plaintexts,
    //       but leading to more decrypt calls and worse performance
    //     - Closer to 6, we expect fewer "false positives" returned in queries,
    //       leading to fewer decrypt calls and better performance,
    //       but it is easier to identify which beacon values encode distinct plaintexts.
    //    As an example, we will choose 5.
    //    Values stored in aws_dbe_b_stateAndHasTestResult will be 5 bits long (0x00 - 0x1f)
    //    There will be 2^5 = 32 possible HMAC values.
    //    With a well-distributed dataset (112 values), for a particular beacon we expect
    //    (112/32) = 3.5 combinations of abbreviation + true/false attribute
    //    sharing that beacon value.
    StandardBeacon stateAndHasTestResultBeacon = StandardBeacon
      .builder()
      // This name is the same as our virtual field's name above
      .name("stateAndHasTestResult")
      .bitLength(5)
      .build();

    // 5. Configure Keystore.
    //    This example expects that you have already set up a KeyStore with a single branch key.
    //    See the "CreateKeyStoreTableExample" and "CreateKeyStoreKeyExample" files for how to do this.
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

      // 6. Create BeaconConfig.
      //    The BeaconConfig holds the list of beacons on the table.
      //    The BeaconConfig also stores information about the keystore.
      //    BeaconConfig must be provided:
      //      - keyStore: The keystore configured in the previous step.
      //      - keySource: A configuration for the key source.
      //        For simple use cases, use BeaconKeySource.singleBeaconKey, which uses one beacon
      //        key for every item. That is the approach this example takes.
      //        For use cases where you want to use different beacon keys depending on the data
      //        (for example if your table holds data for multiple tenants, and you want to use
      //        a different beacon key per tenant), use BeaconKeySource.multipleBeaconKeys:
      //          https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/searchable-encryption-multitenant.html
      //    We also provide our standard beacon list and virtual fields here.
      BeaconConfig beaconConfig = BeaconConfig
        .builder()
        .virtualFields(stateAndHasTestResultField)
        .standardBeacons(stateAndHasTestResultBeacon)
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

      // 7. Create a Hierarchical Keyring
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

      // 8. Decide how each attribute of your items is protected. BasicPutGetExample
      //    explains each action (encryptAndSign, signOnly, signAndIncludeInEncryptionContext,
      //    doNothing), and why the partition and sort keys get none.
      //    Attributes used in beacons must use encryptAndSign.
      //    Every attribute you write must have an action; writing an item with any other attribute
      //    fails.

      // Build the schema from these choices.
      ItemEncryptionSchema schema = ItemEncryptionSchema
        .builder()
        .partitionKeyName("customer_id")
        .sortKeyName("create_time")
        // Beaconized attributes must be encrypted
        .encryptAndSign("state", "hasTestResult")
        .build();

      // 9. Create the DynamoDB Encryption configuration for the table we will be writing to.
      //    The beacon configuration is added to the table configuration.
      DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
        .builder()
        .tableName(tableName)
        .logicalTableName(tableName)
        .schema(schema)
        .keyring(kmsKeyring)
        .beaconConfig(beaconConfig)
        .build();

      // 10. Create test items

      // Create item with hasTestResult=true
      Map<String, AttributeValue> itemWithHasTestResult = Map.of(
        "customer_id",
        AttributeValue.fromS("ABC-123"),
        "create_time",
        AttributeValue.fromN("1681495205"),
        "state",
        AttributeValue.fromS("CA"),
        "hasTestResult",
        AttributeValue.fromBool(true)
      );

      // Create item with hasTestResult=false
      Map<String, AttributeValue> itemWithNoHasTestResult = Map.of(
        "customer_id",
        AttributeValue.fromS("DEF-456"),
        "create_time",
        AttributeValue.fromN("1681495205"),
        "state",
        AttributeValue.fromS("CA"),
        "hasTestResult",
        AttributeValue.fromBool(false)
      );

      // 11. If developing or debugging, verify config by checking virtual field values directly
      DynamoDbEncryptionTransforms transformClient =
        DynamoDbEncryptionTransforms.builder().tableConfigs(config).build();

      // resolveCompoundBeacons returns an empty map because no compound beacons are configured
      assert transformClient
        .resolveCompoundBeacons(tableName, itemWithHasTestResult)
        .isEmpty();

      // Verify that resolveVirtualFields returns the expected value
      Map<String, String> expectedVirtualFields = Map.of(
        "stateAndHasTestResult",
        "CAt"
      );
      assert transformClient
        .resolveVirtualFields(tableName, itemWithHasTestResult)
        .equals(expectedVirtualFields);

      // 12. Create the DynamoDB Encryption Interceptor
      DynamoDbEncryptionInterceptor encryptionInterceptor =
        DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();

      // 13. Create a new AWS SDK DynamoDB client using the DynamoDB Encryption Interceptor above
      try (
        DynamoDbClient dynamoDbClient = DynamoDbClient
          .builder()
          .overrideConfiguration(overrides ->
            overrides.addExecutionInterceptor(encryptionInterceptor)
          )
          .build()
      ) {
        // 14. Put two items into our table using the above client.
        //     The two items will differ only in their `customer_id` attribute (primary key)
        //         and their `hasTestResult` attribute.
        //     We will query against these items to demonstrate how to use our setup above
        //         to query against our `stateAndHasTestResult` beacon.
        //     Before the item gets sent to DynamoDB, it will be encrypted
        //         client-side, according to our configuration.
        //     Since our configuration includes a beacon on a virtual field named
        //         `stateAndHasTestResult`, the client will add an attribute
        //         to the item with name `aws_dbe_b_stateAndHasTestResult`.
        //         Its value will be an HMAC truncated to as many bits as the
        //         beacon's `bitLength` setting; i.e. 5.

        PutItemRequest itemWithHasTestResultPutRequest = PutItemRequest
          .builder()
          .tableName(tableName)
          .item(itemWithHasTestResult)
          .build();

        dynamoDbClient.putItem(itemWithHasTestResultPutRequest);

        PutItemRequest itemWithNoHasTestResultPutRequest = PutItemRequest
          .builder()
          .tableName(tableName)
          .item(itemWithNoHasTestResult)
          .build();

        dynamoDbClient.putItem(itemWithNoHasTestResultPutRequest);

        // 15. Query by stateAndHasTestResult attribute.
        //     Note that we are constructing the query as if we were querying on plaintext values.
        //     However, the DynamoDB encryption client will detect that this attribute name has a
        //     beacon configured. The client will add the beaconized attribute name and attribute
        //     value to the query, and transform the query to use the beaconized name and value.
        //     Internally, the client will query for and receive all items with a matching HMAC
        //     value in the beacon field. This may include a number of "false positives" with
        //     different ciphertext, but the same truncated HMAC.
        //     e.g. if truncate(HMAC("CAt"), 5) == truncate(HMAC("DCf"), 5), the query will return
        //     both items.
        //     The client will decrypt all returned items to determine which ones have the expected
        //     attribute values, and only surface items with the correct plaintext to the user.
        //     This procedure is internal to the client and is abstracted away from the user;
        //     e.g. the user will only see "CAt" and never "DCf", though the actual query returned
        //     both.
        Map<String, String> expressionAttributeNames = Map.of(
          "#stateAndHasTestResult",
          "stateAndHasTestResult"
        );
        Map<String, AttributeValue> expressionAttributeValues = Map.of(
          // We are querying for the item with `state`="CA" and `hasTestResult`=`true`.
          // Since we added virtual parts as `state` then `hasTestResult`,
          //     we must write our query expression in the same order.
          // We constructed our virtual field as `state`+`hasTestResult`,
          //     so we add the two parts in that order.
          // Since we also created a virtual transform that truncated `hasTestResult`
          //     to its length-1 prefix, i.e. "true" -> "t",
          //     we write that field as its length-1 prefix in the query.
          ":stateAndHasTestResult",
          AttributeValue.fromS("CAt")
        );

        QueryRequest queryRequest = QueryRequest
          .builder()
          .tableName(tableName)
          .indexName(GSI_NAME)
          .keyConditionExpression(
            "#stateAndHasTestResult = :stateAndHasTestResult"
          )
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

        // Validate only 1 item was returned: the item with the expected attributes. This also
        // fails if every attempt came back empty.
        assert attributeValues.size() == 1;
        Map<String, AttributeValue> returnedItem = attributeValues.get(0);
        // Validate the item has the expected attributes
        assert returnedItem.get("state").s().equals("CA");
        assert returnedItem.get("hasTestResult").bool();
      }
    }
  }

  public static void main(String[] args) {
    if (args.length < 4) {
      throw new IllegalArgumentException(
        "To run this example, include tableName as args[0], branchKeyId as args[1], branchKeyWrappingKmsKeyArn as args[2], and keyStoreTableName as args[3]"
      );
    }
    String tableName = args[0];
    String branchKeyId = args[1];
    String branchKeyWrappingKmsKeyArn = args[2];
    String keyStoreTableName = args[3];
    putAndQueryItems(
      tableName,
      branchKeyId,
      branchKeyWrappingKmsKeyArn,
      keyStoreTableName
    );
  }
}
