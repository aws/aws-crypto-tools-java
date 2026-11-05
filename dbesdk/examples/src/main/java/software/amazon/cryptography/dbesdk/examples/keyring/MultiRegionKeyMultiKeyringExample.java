package software.amazon.cryptography.dbesdk.examples.keyring;

import java.util.HashMap;
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
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkMultiKeyring;

/*
 This example sets up DynamoDB Encryption for the AWS SDK client using the MRK multi-keyring. This
 keyring takes in multiple AWS KMS MRKs (multi-region keys) or regular AWS KMS keys (single-region
 keys) and uses them to encrypt and decrypt data. Data encrypted using an MRK multi-keyring can be
 decrypted using any of its component keys. If a component key is an MRK with a replica in a second
 region, the replica key can also be used to decrypt data.

 For more information on MRKs, see
 https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html

 For more information on multi-keyrings, see
 https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-multi-keyring.html

 This example creates a new MRK multi-keyring consisting of one MRK (labeled as the "generator
 keyring") and one single-region key (labeled as the only "child keyring"). The MRK also has a
 replica in a second region.

 This example encrypts a test item using the MRK multi-keyring and puts the encrypted item to the
 provided DynamoDB table. Then, it gets the item from the table and decrypts it using three
 different configs:
   1. The MRK multi-keyring, where the MRK key is used to decrypt
   2. Another MRK multi-keyring, where the replica MRK key is used to decrypt
   3. Another MRK multi-keyring, where the single-region key that was present
      in the original MRK multi-keyring is used to decrypt

 Running this example requires access to the DynamoDB Table whose name is provided in CLI arguments. This
 table must be configured with the following primary key configuration:
   - Partition key is named "partition_key" with type (S)
   - Sort key is named "sort_key" with type (N)

 This example demonstrates multi-region use cases. As a result, it requires that you have a default
 region set in your AWS client. You can set a default region through the AWS CLI with
 `aws configure set region [region-name]`
 e.g.
 `aws configure set region us-west-2`
 For more information on using AWS CLI to set config, see
 https://awscli.amazonaws.com/v2/documentation/api/latest/reference/configure/set.html
*/
public class MultiRegionKeyMultiKeyringExample {

  public static void putAndGetItem(
    String tableName,
    String multiRegionKeyArn,
    String singleRegionKeyArn,
    String multiRegionKeyReplicaArn
  ) {
    // 1. Create a single MRK multi-keyring using the MRK arn and the single-region key arn.
    // Create the multi-keyring, using the MRK as the generator key,
    //   and the single-region key as a child key.
    // Note that the generator key will generate and encrypt a plaintext data key
    //   and all child keys will only encrypt that same plaintext data key.
    // As such, you must have permission to call KMS:GenerateDataKey on your generator key
    //   and permission to call KMS:Encrypt on all child keys.
    // For more information, see the AWS docs on multi-keyrings above.
    final Keyring awsKmsMultiRegionKeyring = AwsKmsMrkMultiKeyring
      .builder()
      .generator(multiRegionKeyArn)
      .kmsKeyIds(singleRegionKeyArn)
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
      .keyring(awsKmsMultiRegionKeyring)
      .build();

    // 5. Create the DynamoDB Encryption Interceptor
    final DynamoDbEncryptionInterceptor encryptionInterceptor =
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
      //    The data key protecting this item will be encrypted
      //    with all the KMS Keys in this keyring, so that it can be
      //    decrypted with any one of those KMS Keys.
      final Map<String, AttributeValue> item = new HashMap<>();
      item.put(
        "partition_key",
        AttributeValue
          .builder()
          .s(ExampleUtils.uniquePartitionKey("awsKmsMrkMultiKeyringItem"))
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

      // 8. Get the item back from our table using the client.
      //    The client will decrypt the item client-side using the MRK
      //    and return back the original item.
      //    Since the generator key is the first available key in the keyring,
      //    that is the KMS Key that will be used to decrypt this item.
      final Map<String, AttributeValue> keyToGet = new HashMap<>();
      keyToGet.put(
        "partition_key",
        AttributeValue
          .builder()
          .s(ExampleUtils.uniquePartitionKey("awsKmsMrkMultiKeyringItem"))
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

      // 9. Create a MRK keyring using the replica MRK arn.
      //    We will use this to demonstrate that the replica MRK
      //    can decrypt data created with the original MRK,
      //    even when the replica MRK was not present in the
      //    encrypting multi-keyring.
      final Keyring onlyReplicaKeyMultiRegionKeyring = AwsKmsMrkMultiKeyring
        .builder()
        .kmsKeyIds(multiRegionKeyReplicaArn)
        .build();

      // 10. Create a new config and client using the MRK keyring.
      //     This is the same setup as above, except we provide the MRK keyring to the config.
      final DynamoDbTableEncryptionConfig onlyReplicaKeyConfig =
        DynamoDbTableEncryptionConfig
          .builder()
          .tableName(tableName)
          .logicalTableName(tableName)
          .schema(schema)
          // Only replica keyring added here
          .keyring(onlyReplicaKeyMultiRegionKeyring)
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
        // 11. Get the item back from our table using the client configured with the replica.
        //    The client will decrypt the item client-side using the replica MRK
        //    and return back the original item.
        final Map<String, AttributeValue> onlyReplicaKeyKeyToGet = new HashMap<>();
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

        // 12. Create an AWS KMS keyring using the single-region key ARN.
        //     We will use this to demonstrate that the single-region key
        //     can decrypt data created with the MRK multi-keyring,
        //     since it is present in the keyring used to encrypt.
        final Keyring onlySingleRegionKeyKeyring = AwsKmsMrkMultiKeyring
          .builder()
          .kmsKeyIds(singleRegionKeyArn)
          .build();

        // 13. Create a new config and client using the AWS KMS keyring.
        //     This is the same setup as above, except we provide the AWS KMS keyring to the config.
        final DynamoDbTableEncryptionConfig onlySingleRegionKeyConfig =
          DynamoDbTableEncryptionConfig
            .builder()
            .tableName(tableName)
            .logicalTableName(tableName)
            .schema(schema)
            // Only single-region key keyring added here
            .keyring(onlySingleRegionKeyKeyring)
            .build();

        final DynamoDbEncryptionInterceptor onlySingleRegionKeyEncryptionInterceptor =
          DynamoDbEncryptionInterceptor
            .builder()
            .tableConfigs(onlySingleRegionKeyConfig)
            .build();

        try (
          DynamoDbClient onlySingleRegionKeyDynamoDbClient = DynamoDbClient
            .builder()
            .overrideConfiguration(overrides ->
              overrides.addExecutionInterceptor(onlySingleRegionKeyEncryptionInterceptor)
            )
            .build()
        ) {
          // 14. Get the item back from our table using the client configured with the AWS KMS keyring.
          //     The client will decrypt the item client-side using the single-region key
          //     and return back the original item.
          final Map<String, AttributeValue> onlySingleRegionKeyKeyToGet = new HashMap<>();
          onlySingleRegionKeyKeyToGet.put(
            "partition_key",
            AttributeValue
              .builder()
              .s(ExampleUtils.uniquePartitionKey("awsKmsMrkMultiKeyringItem"))
              .build()
          );
          onlySingleRegionKeyKeyToGet.put("sort_key", AttributeValue.builder().n("0").build());
          final GetItemRequest onlySingleRegionKeyGetRequest = GetItemRequest
            .builder()
            .key(onlySingleRegionKeyKeyToGet)
            .tableName(tableName)
            .build();

          final GetItemResponse onlySingleRegionKeyGetResponse = onlySingleRegionKeyDynamoDbClient.getItem(
            onlySingleRegionKeyGetRequest
          );

          // Demonstrate that GetItem succeeded and returned the decrypted item
          final Map<String, AttributeValue> onlySingleRegionKeyReturnedItem =
            onlySingleRegionKeyGetResponse.item();
          assert onlySingleRegionKeyReturnedItem
            .get("sensitive_data")
            .s()
            .equals("encrypt and sign me!");
        }
      }
    }
  }

  public static void main(final String[] args) {
    if (args.length < 4) {
      throw new IllegalArgumentException(
        "To run this example, include the table name, multiRegionKeyArn, singleRegionKeyArn, and multiRegionKeyReplicaArn in args"
      );
    }
    final String tableName = args[0];
    final String multiRegionKeyArn = args[1];
    final String singleRegionKeyArn = args[2];
    final String multiRegionKeyReplicaArn = args[3];
    putAndGetItem(tableName, multiRegionKeyArn, singleRegionKeyArn, multiRegionKeyReplicaArn);
  }
}
