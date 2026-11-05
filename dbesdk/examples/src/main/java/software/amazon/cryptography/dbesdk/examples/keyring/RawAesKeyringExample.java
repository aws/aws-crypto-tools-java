package software.amazon.cryptography.dbesdk.examples.keyring;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
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
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/*
 This example sets up DynamoDB Encryption for the AWS SDK client using the raw AES Keyring. This
 keyring takes in an AES key and uses that key to protect the data keys that encrypt and decrypt
 DynamoDB table items.

 This example takes in an `aesKeyBytes` parameter. This parameter should be a 256-bit AES key as a
 byte[]. If this example is run through the class' main method, it will create a new key. In
 practice, users of this library should not randomly generate a key, and should instead retrieve an
 existing key from a secure key management system (e.g. an HSM).

 This example encrypts a test item using the provided AES key and puts the encrypted item to the
 provided DynamoDB table. Then, it gets the item from the table and decrypts it.

 Running this example requires access to the DynamoDB Table whose name is provided in CLI arguments. This
 table must be configured with the following primary key configuration:
   - Partition key is named "partition_key" with type (S)
   - Sort key is named "sort_key" with type (N)
*/
public class RawAesKeyringExample {

  public static void putAndGetItem(
    String tableName,
    byte[] aesKeyBytes
  ) {
    // 1. Create the keyring.
    //    The DynamoDB encryption client uses this to encrypt and decrypt items.
    final Keyring rawAesKeyring = RawAesKeyring
      .builder()
      .keyName("my-aes-key-name")
      .keyNamespace("my-key-namespace")
      .wrappingKey(SecretBytes.copyOf(aesKeyBytes))
      .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
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
      .keyring(rawAesKeyring)
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
      //    client-side, according to our configuration.
      final Map<String, AttributeValue> item = new HashMap<>();
      item.put(
        "partition_key",
        AttributeValue
          .builder()
          .s(ExampleUtils.uniquePartitionKey("rawAesKeyringItem"))
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

      // 8. Get the item back from our table using the same client.
      //    The client will decrypt the item client-side, and return
      //    back the original item.
      final Map<String, AttributeValue> keyToGet = new HashMap<>();
      keyToGet.put(
        "partition_key",
        AttributeValue
          .builder()
          .s(ExampleUtils.uniquePartitionKey("rawAesKeyringItem"))
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
    }
  }

  public static void main(final String[] args) {
    if (args.length < 1) {
      throw new IllegalArgumentException(
        "To run this example, include the table name in args"
      );
    }
    final String tableName = args[0];

    // Generate a new AES key
    final byte[] aesKeyBytes = generateAesKeyBytes();

    putAndGetItem(tableName, aesKeyBytes);
  }

  static byte[] generateAesKeyBytes() {
    // This example uses the JCA KeyGenerator to generate the key bytes.
    // In practice, you should not generate this key in your code, and should instead
    //     retrieve this key from a secure key management system (e.g. HSM).
    // This key is created here for example purposes only and should not be used for any other purpose.
    final KeyGenerator aesKeyGenerator;
    try {
      aesKeyGenerator = KeyGenerator.getInstance("AES");
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException(
        "This JVM does not support AES key generation",
        exception
      );
    }
    aesKeyGenerator.init(256, new SecureRandom());
    final SecretKey encryptionKey = aesKeyGenerator.generateKey();
    return encryptionKey.getEncoded();
  }
}
