package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.keyring;

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
import software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.ExampleUtils;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkDiscoveryMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.DiscoveryFilter;

/**
 * This example sets up a MRK discovery multi-keyring to decrypt data using the DynamoDB encryption
 * client. A discovery keyring is not provided with any wrapping keys; instead, it recognizes the KMS
 * key that was used to encrypt a data key, and asks KMS to decrypt with that KMS key. Discovery
 * keyrings cannot be used to encrypt data.
 *
 * <p>For more information on discovery keyrings, see
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-kms-keyring.html#kms-keyring-discovery
 *
 * <p>This example encrypts an item using an MRK multi-keyring and puts the encrypted item to the
 * configured DynamoDB table. Then, it gets the item from the table and decrypts it using the
 * discovery keyring.
 *
 * <p>Running this example requires access to the DynamoDB Table whose name is provided in CLI arguments. This
 * table must be configured with the following primary key configuration:
 *   - Partition key is named "partition_key" with type (S)
 *   - Sort key is named "sort_key" with type (N)
 */
public class MultiRegionKeyDiscoveryMultiKeyringExample {

  public static void putAndGetItem(
    String tableName,
    String keyArn,
    List<String> accountIds,
    List<String> regions
  ) {
    // 1. Create a single MRK multi-keyring using the key arn.
    //    Although this example demonstrates use of the MRK discovery multi-keyring,
    //    a discovery keyring cannot be used to encrypt. So we will need to construct
    //    a non-discovery keyring for this example to encrypt. For more information on MRK
    //    multi-keyrings, see the MultiRegionKeyMultiKeyringExample in this directory.
    //    Though this is an "MRK multi-keyring", we do not need to provide multiple keys,
    //    and can use single-region KMS keys. We will provide a single key here; this
    //    can be either an MRK or a single-region key.
    Keyring encryptKeyring = AwsKmsMrkMultiKeyring
      .builder()
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
      .schema(schema)
      .keyring(encryptKeyring)
      .build();

    // 5. Create the DynamoDB Encryption Interceptor
    DynamoDbEncryptionInterceptor encryptionInterceptor =
      DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();

    // 6. Create a new AWS SDK DynamoDB client using the DynamoDB Encryption Interceptor above
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
      Map<String, AttributeValue> item = Map.of(
        "partition_key",
        AttributeValue.fromS(
          ExampleUtils.uniquePartitionKey("awsKmsMrkDiscoveryMultiKeyringItem")
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

      // 8. Construct a discovery filter.
      //    A discovery filter limits the set of encrypted data keys
      //    the keyring can use to decrypt data.
      //    We will only let the keyring use keys in the selected AWS accounts
      //    and in the `aws` partition.
      //    This is the suggested config for most users; for more detailed config, see
      //      https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-kms-keyring.html#kms-keyring-discovery
      DiscoveryFilter discoveryFilter = DiscoveryFilter.of(accountIds, "aws");

      // 9. Construct a discovery keyring.
      //    Note that we choose to use the MRK discovery multi-keyring, even though
      //    our original keyring used a single KMS key.
      Keyring decryptKeyring = AwsKmsMrkDiscoveryMultiKeyring
        .builder()
        .discoveryFilter(discoveryFilter)
        .regions(regions)
        .build();

      // 10. Create new DynamoDB config and client using the decrypt discovery keyring.
      //     This is the same as the above config, except we pass in the decrypt keyring.
      DynamoDbTableEncryptionConfig configForDecrypt =
        DynamoDbTableEncryptionConfig
          .builder()
          .tableName(tableName)
          .schema(schema)
          // Add decrypt keyring here
          .keyring(decryptKeyring)
          .build();

      DynamoDbEncryptionInterceptor encryptionInterceptorForDecrypt =
        DynamoDbEncryptionInterceptor
          .builder()
          .tableConfigs(configForDecrypt)
          .build();

      try (
        DynamoDbClient decryptingDynamoDbClient = DynamoDbClient
          .builder()
          .overrideConfiguration(overrides ->
            overrides.addExecutionInterceptor(encryptionInterceptorForDecrypt)
          )
          .build()
      ) {
        // 11. Get the item back from our table using the client.
        //     The client will retrieve encrypted items from the DynamoDB table, then
        //     detect the KMS key that was used to encrypt their data keys.
        //     The client will make a request to KMS to decrypt with the encrypting KMS key.
        //     If the client has permission to decrypt with the KMS key,
        //     the client will decrypt the item client-side using the keyring
        //     and return the original item.
        Map<String, AttributeValue> keyToGet = Map.of(
          "partition_key",
          AttributeValue.fromS(
            ExampleUtils.uniquePartitionKey(
              "awsKmsMrkDiscoveryMultiKeyringItem"
            )
          ),
          "sort_key",
          AttributeValue.fromN("0")
        );
        GetItemRequest getRequest = GetItemRequest
          .builder()
          .key(keyToGet)
          .tableName(tableName)
          .build();

        GetItemResponse getResponse = decryptingDynamoDbClient.getItem(
          getRequest
        );

        // Demonstrate that GetItem succeeded and returned the decrypted item
        Map<String, AttributeValue> returnedItem = getResponse.item();
        assert returnedItem
          .get("sensitive_data")
          .s()
          .equals("encrypt and sign me!");
      }
    }
  }

  public static void main(String[] args) {
    if (args.length < 4) {
      throw new IllegalArgumentException(
        "To run this example, include the table name, multiRegionKeyArn, accounts, and region in args"
      );
    }
    String tableName = args[0];
    String multiRegionKeyArn = args[1];

    // We will assume only 1 AWS account and 1 region will be passed into args.
    // To add more of either, change this number, then pass them into args.
    int numberOfAwsAccounts = 1;
    int numberOfRegions = 1;

    int firstAccountIndex = 2; // 2 because args[0] is tableName and args[1] is multiRegionKeyArn
    List<String> accounts = List
      .of(args)
      .subList(firstAccountIndex, firstAccountIndex + numberOfAwsAccounts);
    int firstRegionIndex = firstAccountIndex + numberOfAwsAccounts;
    List<String> regions = List
      .of(args)
      .subList(firstRegionIndex, firstRegionIndex + numberOfRegions);
    putAndGetItem(tableName, multiRegionKeyArn, accounts, regions);
  }
}
