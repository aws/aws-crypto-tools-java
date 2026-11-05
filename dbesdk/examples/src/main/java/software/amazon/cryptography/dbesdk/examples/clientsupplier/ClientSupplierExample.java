package software.amazon.cryptography.dbesdk.examples.clientsupplier;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbesdk.examples.ExampleUtils;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkDiscoveryMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.DiscoveryFilter;

/*
 This example sets up an MRK multi-keyring and an MRK discovery multi-keyring using a custom client
 supplier. A custom client supplier grants users access to more granular configuration aspects of
 their authentication details and KMS client. In this example, we create a simple custom client
 supplier that authenticates with a different IAM role based on the region of the KMS key.

 This example creates a MRK multi-keyring configured with a custom client supplier using a single
 MRK and puts an encrypted item to the table. Then, it creates a MRK discovery multi-keyring to
 decrypt the item and retrieves the item from the table.

 Running this example requires access to the DynamoDB Table whose name is provided in CLI arguments. This
 table must be configured with the following primary key configuration:
   - Partition key is named "partition_key" with type (S)
   - Sort key is named "sort_key" with type (N)
*/
public class ClientSupplierExample {

  public static void putAndGetItem(
    String tableName,
    String keyArn,
    List<String> accountIds,
    List<String> regions
  ) {
    // 1. Create a single MRK multi-keyring.
    //    This can be either a single-region KMS key or an MRK.
    //    For this example to succeed, the key's region must either
    //    1) be in the regions list, or
    //    2) the key must be an MRK with a replica defined
    //    in a region in the regions list, and the client
    //    must have the correct permissions to access the replica.
    // Create the multi-keyring using our custom client supplier
    // defined in the RegionalRoleClientSupplier class in this directory.
    // Note: RegionalRoleClientSupplier will internally use the keyArn's region
    // to retrieve the correct IAM role.
    final Keyring multiRegionKeyringWithClientSupplier = AwsKmsMrkMultiKeyring
      .builder()
      .clientSupplier(new RegionalRoleClientSupplier())
      .generator(keyArn)
      .build();

    // 2. Decide how each attribute of your items is protected. Give each attribute one of these
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
    //    Every attribute you write must either have an action or start with the prefix set in the
    //    next step; writing an item with any other attribute fails.
    //
    //    Do not give the partition key or the sort key (together, the table's primary key) an
    //    action. DynamoDB needs to read them to find the item, so they can never be encrypted, and
    //    the library always signs them for you. By default they are signed like signOnly, and their
    //    values are still handed to your keyring, in an encoded form. If you call
    //    signAndIncludePrimaryKeysInEncryptionContext(true), they are signed like
    //    signAndIncludeInEncryptionContext instead: their values are handed to your keyring as
    //    plain text, and you can give other attributes the signAndIncludeInEncryptionContext
    //    action.

    // 3. Decide which attributes are left out of the signature. Two separate settings do this. They
    //    do different jobs, and you can use either one, both, or neither:
    //
    //    - doNothingPrefix(":") is a naming rule. Every attribute whose name starts with this text
    //      is treated as doNothing, without being listed anywhere. It lets you add new unsigned
    //      attributes later just by naming them with the prefix, with no configuration change. Pick
    //      the prefix before you write any items, and do not change it afterwards.
    //
    //    - doNothing("name", ...) lists specific attributes by name, for unsigned attributes whose
    //      names do not start with the prefix. Never remove a name from this list while items that
    //      have that attribute may still be in the table, or reading those items fails. To add a
    //      name, first update the configuration on every reader, and only then start writing the
    //      new attribute.
    //
    //    This example sets the prefix ":" so that unsigned attributes can be added later. The items
    //    it writes do not have any yet.

    // Build the schema from the choices above.
    final ItemEncryptionSchema schema = ItemEncryptionSchema
      .builder()
      .partitionKeyName("partition_key")
      .sortKeyName("sort_key")
      .encryptAndSign("sensitive_data")
      .doNothingPrefix(":")
      .build();

    // 4. Create the DynamoDB Encryption configuration for the table we will be writing to.
    final DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .logicalTableName(tableName)
      .schema(schema)
      .keyring(multiRegionKeyringWithClientSupplier)
      .build();

    // 5. Create the DynamoDB Encryption Interceptor.
    final DynamoDbEncryptionInterceptor encryptionInterceptor =
      DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();

    // 6. Create a new AWS SDK DynamoDB client using the DynamoDB Encryption Interceptor above.
    try (
      DynamoDbClient dynamoDbClient = DynamoDbClient
        .builder()
        .overrideConfiguration(overrides ->
          overrides.addExecutionInterceptor(encryptionInterceptor)
        )
        .build()
    ) {
      // 7. Put an item into our table using the above client.
      //    Before the item gets sent to DynamoDB, it will be encrypted
      //    client-side using the MRK multi-keyring.
      //    The data key protecting this item will be encrypted
      //    with all the KMS Keys in this keyring, so that it can be
      //    decrypted with any one of those KMS Keys.
      final Map<String, AttributeValue> item = new HashMap<>();
      item.put(
        "partition_key",
        AttributeValue
          .builder()
          .s(ExampleUtils.uniquePartitionKey("clientSupplierItem"))
          .build()
      );
      item.put("sort_key", AttributeValue.builder().n("0").build());
      item.put(
        "sensitive_data",
        AttributeValue.builder().s("encrypt and sign me!").build()
      );
      final PutItemRequest putRequest = PutItemRequest
        .builder()
        .tableName(tableName)
        .item(item)
        .build();
      dynamoDbClient.putItem(putRequest);

      // 8. Get the item back from our table using the same keyring.
      //    The client will decrypt the item client-side using the MRK
      //    and return the original item.
      final Map<String, AttributeValue> keyToGet = new HashMap<>();
      keyToGet.put(
        "partition_key",
        AttributeValue
          .builder()
          .s(ExampleUtils.uniquePartitionKey("clientSupplierItem"))
          .build()
      );
      keyToGet.put("sort_key", AttributeValue.builder().n("0").build());
      final GetItemRequest getRequest = GetItemRequest
        .builder()
        .key(keyToGet)
        .tableName(tableName)
        .build();
      final GetItemResponse getResponse = dynamoDbClient.getItem(getRequest);

      // Demonstrate that GetItem succeeded and returned the decrypted item
      final Map<String, AttributeValue> returnedItem = getResponse.item();
      assert returnedItem.get("sensitive_data").s().equals("encrypt and sign me!");

      // 9. Create a MRK discovery multi-keyring with a custom client supplier.
      //    A discovery MRK multi-keyring will be composed of
      //    multiple discovery MRK keyrings, one for each region.
      //    Each component keyring has its own KMS client in a particular region.
      //    When we provide a client supplier to the multi-keyring, all component
      //    keyrings will use that client supplier configuration.
      //    In our tests, we make `keyArn` an MRK with a replica, and
      //    provide only the replica region in our discovery filter.
      final DiscoveryFilter discoveryFilter = DiscoveryFilter.of(
        accountIds,
        "aws"
      );

      final Keyring multiRegionDiscoveryKeyringWithClientSupplier =
        AwsKmsMrkDiscoveryMultiKeyring
          .builder()
          .clientSupplier(new RegionalRoleClientSupplier())
          .discoveryFilter(discoveryFilter)
          .regions(regions)
          .build();

      // 10. Create a new config and client using the discovery keyring.
      //     This is the same setup as above, except we provide the discovery keyring to the config.
      final DynamoDbTableEncryptionConfig onlyReplicaKeyConfig =
        DynamoDbTableEncryptionConfig
          .builder()
          .tableName(tableName)
          .logicalTableName(tableName)
          .schema(schema)
          // Provide discovery keyring here
          .keyring(multiRegionDiscoveryKeyringWithClientSupplier)
          .build();

      final DynamoDbEncryptionInterceptor onlyReplicaKeyEncryptionInterceptor =
        DynamoDbEncryptionInterceptor
          .builder()
          .tableConfigs(onlyReplicaKeyConfig)
          .build();

      try (
        DynamoDbClient onlyReplicaKeyDynamoDbClient = DynamoDbClient
          .builder()
          .overrideConfiguration(overrides ->
            overrides.addExecutionInterceptor(onlyReplicaKeyEncryptionInterceptor)
          )
          .build()
      ) {
        // 11. Get the item back from our table using the discovery keyring client. The client will
        // decrypt the item client-side using the keyring, and return the original item. The discovery
        // keyring will only use KMS keys in the provided regions and AWS accounts. Since we have
        // provided it with a custom client supplier which uses different IAM roles based on the key
        // region, the discovery keyring will use a particular IAM role to decrypt based on the region
        // of the KMS key it uses to decrypt. We read the item written by MultiRegionKeyMultiKeyringExample
        // (partition_key "awsKmsMrkMultiKeyringItem") to demonstrate discovery across keys this example
        // did not write.
        final Map<String, AttributeValue> onlyReplicaKeyKeyToGet =
          new HashMap<>();
        onlyReplicaKeyKeyToGet.put(
          "partition_key",
          AttributeValue
            .builder()
            .s(ExampleUtils.uniquePartitionKey("awsKmsMrkMultiKeyringItem"))
            .build()
        );
        onlyReplicaKeyKeyToGet.put(
          "sort_key",
          AttributeValue.builder().n("0").build()
        );

        final GetItemRequest onlyReplicaKeyGetRequest = GetItemRequest
          .builder()
          .key(onlyReplicaKeyKeyToGet)
          .tableName(tableName)
          .build();
        final GetItemResponse onlyReplicaKeyGetResponse =
          onlyReplicaKeyDynamoDbClient.getItem(onlyReplicaKeyGetRequest);

        // Demonstrate that GetItem succeeded and returned the decrypted item
        final Map<String, AttributeValue> onlyReplicaKeyReturnedItem =
          onlyReplicaKeyGetResponse.item();
        assert onlyReplicaKeyReturnedItem.get("sensitive_data").s().equals("encrypt and sign me!");
      }
    }
  }

  public static void main(final String[] args) {
    if (args.length < 4) {
      throw new IllegalArgumentException(
        "To run this example, include the table name, keyArn, AWS accounts, and regions in args"
      );
    }
    final String tableName = args[0];
    final String keyArn = args[1];

    // We will assume only 1 AWS account and 1 region will be passed into args.
    // To add more of either, change this number, then pass them into args.
    int numberOfAwsAccounts = 1;
    int numberOfRegions = 1;

    int firstAccountIndex = 2; // 2 because args[0] is tableName and args[1] is keyArn
    final List<String> accounts = new ArrayList<>(
      Arrays
        .asList(args)
        .subList(firstAccountIndex, firstAccountIndex + numberOfAwsAccounts)
    );
    int firstRegionIndex = firstAccountIndex + numberOfAwsAccounts;
    final List<String> regions = new ArrayList<>(
      Arrays
        .asList(args)
        .subList(firstRegionIndex, firstRegionIndex + numberOfRegions)
    );
    putAndGetItem(tableName, keyArn, accounts, regions);
  }
}
