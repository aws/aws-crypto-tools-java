package software.amazon.cryptography.dbesdk.examples.keyring;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
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
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.MultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * This example sets up DynamoDB Encryption for the AWS SDK client using the multi-keyring. This
 * keyring takes in multiple keyrings and uses them to encrypt and decrypt data. Data encrypted with a
 * multi-keyring can be decrypted with any of its component keyrings.
 *
 * <p>For more information on multi-keyrings, see
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-multi-keyring.html
 *
 * <p>This example creates a new multi-keyring consisting of an AWS KMS keyring (labeled the "generator
 * keyring") and a raw AES keyring (labeled as the only "child keyring"). It encrypts a test item
 * using the multi-keyring and puts the encrypted item to the provided DynamoDB table. Then, it gets
 * the item from the table and decrypts it using only the raw AES keyring.
 *
 * <p>This example takes in an `aesKeyBytes` parameter. This parameter should be a 256-bit AES key as a
 * byte[]. If this example is run through the class' main method, it will create a new key. In
 * practice, users of this library should not randomly generate a key, and should instead retrieve an
 * existing key from a secure key management system (e.g. an HSM).
 *
 * <p>Running this example requires access to the DynamoDB Table whose name is provided in CLI arguments. This
 * table must be configured with the following primary key configuration:
 *   - Partition key is named "partition_key" with type (S)
 *   - Sort key is named "sort_key" with type (N)
 */
public class MultiKeyringExample {

  public static void putAndGetItem(
    String tableName,
    String keyArn,
    byte[] aesKeyBytes
  ) {
    // 1. Create the raw AES keyring.
    Keyring rawAesKeyring = RawAesKeyring
      .builder()
      .keyName("my-aes-key-name")
      .keyNamespace("my-key-namespace")
      .wrappingKey(SecretBytes.copyOf(aesKeyBytes))
      .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
      .build();

    // 2. Create the AWS KMS keyring.
    //    We create a MRK multi keyring, as this interface also supports
    //    single-region KMS keys (standard KMS keys),
    //    and creates the KMS client for us automatically.
    Keyring awsKmsMultiRegionKeyring = AwsKmsMrkMultiKeyring
      .builder()
      .generator(keyArn)
      .build();

    // 3. Create the multi-keyring.
    //    We will label the AWS KMS keyring as the generator and the raw AES keyring as the
    //        only child keyring.
    //    You must provide a generator keyring to encrypt data.
    //    You may provide additional child keyrings. Each child keyring will be able to
    //        decrypt data encrypted with the multi-keyring on its own. It does not need
    //        knowledge of any other child keyrings or the generator keyring to decrypt.
    Keyring multiKeyring = MultiKeyring
      .builder()
      .generator(awsKmsMultiRegionKeyring)
      .childKeyrings(rawAesKeyring)
      .build();

    // 4. Decide how each attribute of your items is protected. BasicPutGetExample
    //    explains each action (encryptAndSign, signOnly, signAndIncludeInEncryptionContext,
    //    doNothing), and why the partition and sort keys get none.
    //    Every attribute you write must either have an action or start with the prefix set in the
    //    next step; writing an item with any other attribute fails.

    // 5. Decide which attributes are left out of the signature. Two separate settings do this. They
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

    // 6. Create the DynamoDB Encryption configuration for the table we will be writing to.
    //    Note that this example creates one config/client combination for PUT, and another
    //        for GET. The PUT config uses the multi-keyring, while the GET config uses the
    //        raw AES keyring. This is solely done to demonstrate that a keyring included as
    //        a child of a multi-keyring can be used to decrypt data on its own.
    DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .logicalTableName(tableName)
      .schema(schema)
      // Multi-keyring is added here
      .keyring(multiKeyring)
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
      //    client-side using the multi-keyring.
      //    The item will be encrypted with all wrapping keys in the keyring,
      //    so that it can be decrypted with any one of the keys.
      Map<String, AttributeValue> item = Map.of(
        "partition_key",
        AttributeValue.fromS(
          ExampleUtils.uniquePartitionKey("multiKeyringItem")
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

      // 10. Get the item back from our table using the above client.
      //     The client will decrypt the item client-side using the AWS KMS
      //     keyring, and return back the original item.
      //     Since the generator key is the first available key in the keyring,
      //     that is the key that will be used to decrypt this item.
      Map<String, AttributeValue> keyToGet = Map.of(
        "partition_key",
        AttributeValue.fromS(
          ExampleUtils.uniquePartitionKey("multiKeyringItem")
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

      // 11. Create a new config and client with only the raw AES keyring to GET the item
      //     This is the same setup as above, except the config uses the `rawAesKeyring`.
      DynamoDbTableEncryptionConfig onlyAesKeyringConfig =
        DynamoDbTableEncryptionConfig
          .builder()
          .tableName(tableName)
          .logicalTableName(tableName)
          .schema(schema)
          // Raw AES keyring is added here
          .keyring(rawAesKeyring)
          .build();

      DynamoDbEncryptionInterceptor onlyAesKeyringEncryptionInterceptor =
        DynamoDbEncryptionInterceptor
          .builder()
          .tableConfigs(onlyAesKeyringConfig)
          .build();

      try (
        DynamoDbClient onlyAesKeyringDynamoDbClient = DynamoDbClient
          .builder()
          .overrideConfiguration(overrides ->
            overrides.addExecutionInterceptor(
              onlyAesKeyringEncryptionInterceptor
            )
          )
          .build()
      ) {
        // 12. Get the item back from our table using the client
        //     configured with only the raw AES keyring.
        //     The client will decrypt the item client-side using the raw
        //     AES keyring, and return back the original item.
        Map<String, AttributeValue> onlyAesKeyringKeyToGet = Map.of(
          "partition_key",
          AttributeValue.fromS(
            ExampleUtils.uniquePartitionKey("multiKeyringItem")
          ),
          "sort_key",
          AttributeValue.fromN("0")
        );
        GetItemRequest onlyAesKeyringGetRequest = GetItemRequest
          .builder()
          .key(onlyAesKeyringKeyToGet)
          .tableName(tableName)
          .build();

        GetItemResponse onlyAesKeyringGetResponse =
          onlyAesKeyringDynamoDbClient.getItem(onlyAesKeyringGetRequest);

        // Demonstrate that GetItem succeeded and returned the decrypted item
        Map<String, AttributeValue> onlyAesKeyringReturnedItem =
          onlyAesKeyringGetResponse.item();
        assert onlyAesKeyringReturnedItem
          .get("sensitive_data")
          .s()
          .equals("encrypt and sign me!");
      }
    }
  }

  public static void main(String[] args) {
    if (args.length < 2) {
      throw new IllegalArgumentException(
        "To run this example, include the table name and keyArn in args"
      );
    }
    String tableName = args[0];
    String keyArn = args[1];

    // Generate a new AES key
    byte[] aesKeyBytes = generateAesKeyBytes();

    putAndGetItem(tableName, keyArn, aesKeyBytes);
  }

  private static byte[] generateAesKeyBytes() {
    // This example uses the JCA KeyGenerator to generate the key bytes.
    // In practice, you should not generate this key in your code, and should instead
    //     retrieve this key from a secure key management system (e.g. HSM).
    // This key is created here for example purposes only and should not be used for any other purpose.
    KeyGenerator aesKeyGenerator;
    try {
      aesKeyGenerator = KeyGenerator.getInstance("AES");
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException(
        "This JVM does not support AES key generation",
        exception
      );
    }
    aesKeyGenerator.init(256, new SecureRandom());
    SecretKey encryptionKey = aesKeyGenerator.generateKey();
    return encryptionKey.getEncoded();
  }
}
