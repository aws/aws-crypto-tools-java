package software.amazon.cryptography.dbesdk.examples;

import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkMultiKeyring;

/**
 * This example sets up DynamoDB Encryption for the AWS SDK client
 * and uses the low level PutItem and GetItem DynamoDB APIs to demonstrate
 * putting a client-side encrypted item into DynamoDB
 * and then retrieving and decrypting that item from DynamoDB.
 *
 * <p>Running this example requires access to the DynamoDB Table whose name
 * is provided in CLI arguments.
 * This table must be configured with the following
 * primary key configuration:
 *   - Partition key is named `partitionKeyName` with type (S)
 *   - Sort key is named `sortKeyName` with type (N)
 */
public class BasicPutGetExample {

  public static void putAndGetItem(
    String kmsKeyId,
    String tableName,
    String partitionKeyName,
    String sortKeyName,
    String partitionKeyValue,
    String sortKeyValue
  ) {
    // 1. Create a keyring. The keyring is responsible for protecting the data keys that protect
    // your data. For this example, we use an AWS KMS keyring with the KMS key we want to use. We
    // will create a `AwsKmsMrkMultiKeyring` because it correctly handles both Single-Region and
    // Multi-Region KMS keys.
    Keyring kmsKeyring = AwsKmsMrkMultiKeyring
      .builder()
      .generator(kmsKeyId)
      .build();

    // 2. Decide how each attribute of your items is protected. Give each attribute one of these
    // actions:
    // - encryptAndSign: the value is encrypted, so it cannot be read without the keys your keyring
    //   uses, and it is covered by the item's signature, so any change to it is detected when the
    //   item is read.
    // - signOnly: the value is stored as plain, readable text, but it is covered by the signature,
    //   so any change to it is detected.
    // - signAndIncludeInEncryptionContext: like signOnly, and the value is also handed to your
    //   keyring each time the item is encrypted or decrypted, for example so that a branch key ID
    //   supplier can pick a different key for each tenant. Using this action also requires
    //   signAndIncludePrimaryKeysInEncryptionContext(true) (see below).
    // - doNothing: the value is stored as plain text and is not covered by the signature, so a
    //   change to it is NOT detected.
    // Every attribute you write must either have an action or start with the prefix set in the next
    // step; writing an item with any other attribute fails.
    //
    // Do not give the partition key or the sort key (together, the table's primary key) an action.
    // DynamoDB needs to read them to find the item, so they can never be encrypted, and the library
    // always signs them for you. By default they are signed like signOnly, and their values are
    // still handed to your keyring, in an encoded form. If you call
    // signAndIncludePrimaryKeysInEncryptionContext(true), they are signed like
    // signAndIncludeInEncryptionContext instead: their values are handed to your keyring as plain
    // text, and you can give other attributes the signAndIncludeInEncryptionContext action.

    // 3. Decide which attributes are left out of the signature. Two separate settings do this. They
    // do different jobs, and you can use either one, both, or neither:
    //
    // - doNothingPrefix(":") is a naming rule. Every attribute whose name starts with this text is
    //   treated as doNothing, without being listed anywhere. It lets you add new unsigned
    //   attributes later just by naming them with the prefix, with no configuration change. Pick
    //   the prefix before you write any items, and do not change it afterwards.
    //
    // - doNothing("name", ...) lists specific attributes by name, for unsigned attributes whose
    //   names do not start with the prefix. Never remove a name from this list while items that
    //   have that attribute may still be in the table, or reading those items fails. To add a name,
    //   first update the configuration on every reader, and only then start writing the new
    //   attribute.
    //
    // This example sets the prefix ":". The item it writes has one such attribute, ":attribute3",
    // so that attribute is not signed and does not need to be listed.

    // Build the schema from the choices above.
    ItemEncryptionSchema schema = ItemEncryptionSchema
      .builder()
      .partitionKeyName(partitionKeyName)
      .sortKeyName(sortKeyName)
      .encryptAndSign("attribute1")
      .signOnly("attribute2")
      .doNothingPrefix(":")
      .build();

    // 4. Create the DynamoDB encryption configuration for the table we will write to.
    DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .logicalTableName(tableName)
      .schema(schema)
      .keyring(kmsKeyring)
      // Specifying an algorithm suite is not required, but is shown here to demonstrate how.
      // We recommend the
      // `ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384` suite, which
      // combines AES-GCM with key derivation, ECDSA signing, and key commitment. This is also
      // the default if one is not specified. For more information on supported algorithm
      // suites, see:
      //
      // https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/supported-algorithms.html
      .algorithmSuite(
        AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384
      )
      .build();

    // 5. Build the DynamoDB Encryption Interceptor.
    DynamoDbEncryptionInterceptor encryptionInterceptor =
      DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();

    // 6. Create a new AWS SDK DynamoDB client using the DynamoDB Encryption Interceptor created
    // above.
    try (
      DynamoDbClient dynamoDbClient = DynamoDbClient
        .builder()
        .overrideConfiguration(overrides ->
          overrides.addExecutionInterceptor(encryptionInterceptor)
        )
        .build()
    ) {
      // 7. Put an item into the table using the client created above. Before the item reaches
      // DynamoDB, it will be encrypted client-side according to the configuration above.
      Map<String, AttributeValue> item = Map.of(
        partitionKeyName,
        AttributeValue.fromS(partitionKeyValue),
        sortKeyName,
        AttributeValue.fromN(sortKeyValue),
        "attribute1",
        AttributeValue.fromS("encrypt and sign me!"),
        "attribute2",
        AttributeValue.fromS("sign me!"),
        ":attribute3",
        AttributeValue.fromS("ignore me!")
      );
      PutItemRequest putRequest = PutItemRequest
        .builder()
        .tableName(tableName)
        .item(item)
        .build();

      dynamoDbClient.putItem(putRequest);

      // 8. Get the item back from the table using the same client. The client will decrypt the item
      // client-side on the way back, and return the original plaintext item.
      Map<String, AttributeValue> keyToGet = Map.of(
        partitionKeyName,
        AttributeValue.fromS(partitionKeyValue),
        sortKeyName,
        AttributeValue.fromN(sortKeyValue)
      );
      GetItemRequest getRequest = GetItemRequest
        .builder()
        .key(keyToGet)
        .tableName(tableName)
        // We request a strongly consistent read here because we read immediately after the
        // write (for demonstration). By default, DynamoDB reads are only eventually consistent,
        // so a default read right after a write may not yet see the item. Consult the docs to
        // choose the read consistency appropriate for your application:
        //
        // https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadConsistency.html
        .consistentRead(true)
        .build();

      GetItemResponse getResponse = dynamoDbClient.getItem(getRequest);

      // Demonstrate that GetItem succeeded and returned the decrypted item
      Map<String, AttributeValue> returnedItem = getResponse.item();
      assert returnedItem.get("attribute1").s().equals("encrypt and sign me!");
    }
  }

  public static void main(String[] args) {
    if (args.length < 6) {
      throw new IllegalArgumentException(
        "To run this example, include the kmsKeyId as args[0], tableName as args[1], " +
        "partitionKeyName as args[2], sortKeyName as args[3], partitionKeyValue as args[4], " +
        "sortKeyValue as args[5]"
      );
    }
    String kmsKeyId = args[0];
    String tableName = args[1];
    String partitionKeyName = args[2];
    String sortKeyName = args[3];
    String partitionKeyValue = args[4];
    String sortKeyValue = args[5];
    putAndGetItem(
      kmsKeyId,
      tableName,
      partitionKeyName,
      sortKeyName,
      partitionKeyValue,
      sortKeyValue
    );
  }
}
