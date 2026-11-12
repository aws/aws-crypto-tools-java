package software.amazon.cryptography.dbesdk.examples.clientsupplier;

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

/**
 * This example sets up an MRK multi-keyring and an MRK discovery multi-keyring using a custom client
 * supplier. A custom client supplier grants users access to more granular configuration aspects of
 * their authentication details and KMS client. In this example, we create a simple custom client
 * supplier that authenticates with a different IAM role based on the region of the KMS key.
 *
 * <p>This example creates a MRK multi-keyring configured with a custom client supplier using a single
 * MRK and puts an encrypted item to the table. Then, it creates a MRK discovery multi-keyring to
 * decrypt the item and retrieves the item from the table.
 *
 * <p>Running this example requires access to the DynamoDB Table whose name is provided in CLI arguments. This
 * table must be configured with the following primary key configuration:
 *   - Partition key is named "partition_key" with type (S)
 *   - Sort key is named "sort_key" with type (N)
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
    // to retrieve the correct IAM role. The roles it assumes for each Region are listed in that
    // class; replace them with roles in your account.
    // Both keyrings in this example use this one supplier. The try block closes it, and the STS
    // client it owns, when it ends, so everything that uses either keyring stays inside it.
    try (
      RegionalRoleClientSupplier clientSupplier =
        new RegionalRoleClientSupplier()
    ) {
      Keyring multiRegionKeyringWithClientSupplier = AwsKmsMrkMultiKeyring
        .builder()
        .clientSupplier(clientSupplier)
        .generator(keyArn)
        .build();

      // 2. Decide how each attribute of your items is protected. BasicPutGetExample
      //    explains each action (encryptAndSign, signOnly, signAndIncludeInEncryptionContext,
      //    doNothing), and why the partition and sort keys get none.
      //    Every attribute you write must either have an action or start with the prefix set in the
      //    next step; writing an item with any other attribute fails.

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
      ItemEncryptionSchema schema = ItemEncryptionSchema
        .builder()
        .partitionKeyName("partition_key")
        .sortKeyName("sort_key")
        .encryptAndSign("sensitive_data")
        .doNothingPrefix(":")
        .build();

      // 4. Create the DynamoDB Encryption configuration for the table we will be writing to.
      DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
        .builder()
        .tableName(tableName)
        .logicalTableName(tableName)
        .schema(schema)
        .keyring(multiRegionKeyringWithClientSupplier)
        .build();

      // 5. Create the DynamoDB Encryption Interceptor.
      DynamoDbEncryptionInterceptor encryptionInterceptor =
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
        Map<String, AttributeValue> item = Map.of(
          "partition_key",
          AttributeValue.fromS(
            ExampleUtils.uniquePartitionKey("clientSupplierItem")
          ),
          "sort_key",
          AttributeValue.fromN("0"),
          "sensitive_data",
          AttributeValue.fromS("encrypt and sign me!")
        );
        PutItemRequest putRequest = PutItemRequest
          .builder()
          .tableName(tableName)
          .item(item)
          .build();
        dynamoDbClient.putItem(putRequest);

        // 8. Get the item back from our table using the same keyring.
        //    The client will decrypt the item client-side using the MRK
        //    and return the original item.
        Map<String, AttributeValue> keyToGet = Map.of(
          "partition_key",
          AttributeValue.fromS(
            ExampleUtils.uniquePartitionKey("clientSupplierItem")
          ),
          "sort_key",
          AttributeValue.fromN("0")
        );
        GetItemRequest getRequest = GetItemRequest
          .builder()
          .key(keyToGet)
          .tableName(tableName)
          .build();
        GetItemResponse getResponse = dynamoDbClient.getItem(getRequest);

        // Demonstrate that GetItem succeeded and returned the decrypted item
        Map<String, AttributeValue> returnedItem = getResponse.item();
        assert returnedItem
          .get("sensitive_data")
          .s()
          .equals("encrypt and sign me!");

        // 9. Create a MRK discovery multi-keyring with a custom client supplier.
        //    A discovery MRK multi-keyring will be composed of
        //    multiple discovery MRK keyrings, one for each region.
        //    Each component keyring has its own KMS client in a particular region.
        //    When we provide a client supplier to the multi-keyring, all component
        //    keyrings will use that client supplier configuration.
        //    For the next steps to succeed, `keyArn` must be an MRK with a replica in one of the
        //    regions passed in. The discovery keyring then decrypts the item from step 7 with that
        //    replica.
        DiscoveryFilter discoveryFilter = DiscoveryFilter.of(accountIds, "aws");

        Keyring multiRegionDiscoveryKeyringWithClientSupplier =
          AwsKmsMrkDiscoveryMultiKeyring
            .builder()
            .clientSupplier(clientSupplier)
            .discoveryFilter(discoveryFilter)
            .regions(regions)
            .build();

        // 10. Create a new config and client using the discovery keyring.
        //     This is the same setup as above, except we provide the discovery keyring to the config.
        DynamoDbTableEncryptionConfig onlyReplicaKeyConfig =
          DynamoDbTableEncryptionConfig
            .builder()
            .tableName(tableName)
            .logicalTableName(tableName)
            .schema(schema)
            // Provide discovery keyring here
            .keyring(multiRegionDiscoveryKeyringWithClientSupplier)
            .build();

        DynamoDbEncryptionInterceptor onlyReplicaKeyEncryptionInterceptor =
          DynamoDbEncryptionInterceptor
            .builder()
            .tableConfigs(onlyReplicaKeyConfig)
            .build();

        try (
          DynamoDbClient onlyReplicaKeyDynamoDbClient = DynamoDbClient
            .builder()
            .overrideConfiguration(overrides ->
              overrides.addExecutionInterceptor(
                onlyReplicaKeyEncryptionInterceptor
              )
            )
            .build()
        ) {
          // 11. Get the item written in step 7 back from our table using the discovery keyring client.
          // The client will decrypt the item client-side using the keyring, and return the original
          // item. The discovery keyring will only use KMS keys in the provided regions and AWS
          // accounts. Since we have provided it with a custom client supplier which uses different IAM
          // roles based on the key region, the discovery keyring will use a particular IAM role to
          // decrypt based on the region of the KMS key it uses to decrypt.
          Map<String, AttributeValue> onlyReplicaKeyItemKey = Map.of(
            "partition_key",
            AttributeValue.fromS(
              ExampleUtils.uniquePartitionKey("clientSupplierItem")
            ),
            "sort_key",
            AttributeValue.fromN("0")
          );

          GetItemRequest onlyReplicaKeyGetRequest = GetItemRequest
            .builder()
            .key(onlyReplicaKeyItemKey)
            .tableName(tableName)
            .build();
          GetItemResponse onlyReplicaKeyGetResponse =
            onlyReplicaKeyDynamoDbClient.getItem(onlyReplicaKeyGetRequest);

          // Demonstrate that GetItem succeeded and returned the decrypted item
          Map<String, AttributeValue> onlyReplicaKeyReturnedItem =
            onlyReplicaKeyGetResponse.item();
          assert onlyReplicaKeyReturnedItem
            .get("sensitive_data")
            .s()
            .equals("encrypt and sign me!");
        }
      }
    }
  }

  public static void main(String[] args) {
    if (args.length < 4) {
      throw new IllegalArgumentException(
        "To run this example, include the table name, keyArn, AWS accounts, and regions in args"
      );
    }
    String tableName = args[0];
    String keyArn = args[1];

    // We will assume only 1 AWS account and 1 region will be passed into args.
    // To add more of either, change this number, then pass them into args.
    int numberOfAwsAccounts = 1;
    int numberOfRegions = 1;

    int firstAccountIndex = 2; // 2 because args[0] is tableName and args[1] is keyArn
    List<String> accounts = List
      .of(args)
      .subList(firstAccountIndex, firstAccountIndex + numberOfAwsAccounts);
    int firstRegionIndex = firstAccountIndex + numberOfAwsAccounts;
    List<String> regions = List
      .of(args)
      .subList(firstRegionIndex, firstRegionIndex + numberOfRegions);
    putAndGetItem(tableName, keyArn, accounts, regions);
  }
}
