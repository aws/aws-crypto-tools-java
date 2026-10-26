package software.amazon.cryptography.dbesdk.examples;

import java.util.HashMap;
import java.util.Map;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemResponse;
import software.amazon.cryptography.dbesdk.dynamodbencryption.CryptoAction;
import software.amazon.cryptography.dbesdk.dynamodbencryption.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbesdk.dynamodbencryption.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkMultiKeyring;

/*
  This example sets up DynamoDB Encryption for the AWS SDK client
  and uses the low level PutItem and GetItem DDB APIs to demonstrate
  putting a client-side encrypted item into DynamoDB
  and then retrieving and decrypting that item from DynamoDB.

  Running this example requires access to the DDB Table whose name
  is provided in CLI arguments.
  This table must be configured with the following
  primary key configuration:
    - Partition key is named `partitionKeyName` with type (S)
    - Sort key is named `sortKeyName` with type (N)
 */
public class BasicPutGetExample {

  public static void putItemGetItem(
    String kmsKeyId,
    String ddbTableName,
    String partitionKeyName,
    String sortKeyName,
    String partitionKeyValue,
    String sortKeyValue
  ) {
    // 1. Create a keyring. The keyring is responsible for protecting the data keys that protect
    // your data. For this example, we use an AWS KMS keyring with the KMS key we want to use. We
    // will create a `AwsKmsMrkMultiKeyring` because it correctly handles both Single-Region and
    // Multi-Region KMS keys.
    final Keyring kmsKeyring = AwsKmsMrkMultiKeyring
      .builder()
      .generator(kmsKeyId)
      .build();

    // 2. Configure which attributes are encrypted and/or signed when writing new items. For every
    // attribute that may appear on an item we write to the DynamoDB table, we must explicitly
    // declare how it is treated during item encryption:
    //   - ENCRYPT_AND_SIGN: the attribute is encrypted and included in the signature.
    //   - SIGN_ONLY: the attribute is not encrypted, but is still included in the signature.
    //   - DO_NOTHING: the attribute is neither encrypted nor included in the signature.
    //
    // The partition and sort key attributes must be SIGN_ONLY (a primary-key attribute cannot be
    // encrypted, since DynamoDB needs its plaintext to locate the item, but it is still
    // authenticated). The ":"-prefixed attribute is DO_NOTHING, i.e. left entirely
    // unauthenticated.
    final Map<String, CryptoAction> attributeActionsOnEncrypt = new HashMap<>();
    attributeActionsOnEncrypt.put(partitionKeyName, CryptoAction.SIGN_ONLY); // the partition attribute must be SIGN_ONLY
    attributeActionsOnEncrypt.put(sortKeyName, CryptoAction.SIGN_ONLY); // the sort attribute must be SIGN_ONLY
    attributeActionsOnEncrypt.put("attribute1", CryptoAction.ENCRYPT_AND_SIGN);
    attributeActionsOnEncrypt.put("attribute2", CryptoAction.SIGN_ONLY);
    attributeActionsOnEncrypt.put(":attribute3", CryptoAction.DO_NOTHING);

    // 3. Configure which attributes are expected to be excluded from the signature when reading
    // items. There are two ways to configure this:
    //
    // - (Recommended) `allowedUnsignedAttributePrefix`: when defining the table schema, choose a
    //   distinguishing prefix (such as ":") for every attribute you do NOT want included in the
    //   signature. This has two benefits:
    //   - It is easier to reason about the security and authenticity of an item when all
    //     unauthenticated data is identifiable by attribute name alone.
    //   - To add new unauthenticated attributes in the future, you only need to update
    //     `attributeActionsOnEncrypt` and can start writing the new attribute immediately, with
    //     no other configuration change needed.
    //   Once set, this prefix is not safe to change.
    //
    // - `allowedUnsignedAttributes`: alternatively, you may explicitly list a set of attribute
    //   names to treat as unauthenticated on read. Use this with caution: never remove a name
    //   from the list even after you stop writing it, because older items may still carry that
    //   attribute and the configuration must keep excluding it from the signature scope. To add a
    //   new attribute name, you must deploy the updated list to every reader in the fleet BEFORE
    //   any writer starts writing with that attribute, otherwise a reader that hasn't been
    //   updated will reject the item for carrying an unexpected unsigned attribute.
    //
    // This example designs the table so any ":"-prefixed attribute is unauthenticated.
    final String unsignAttrPrefix = ":";

    // 4. Create the DynamoDB encryption configuration for the table we will write to.
    final Map<String, DynamoDbTableEncryptionConfig> tableConfigs =
      new HashMap<>();
    final DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
      .builder()
      .logicalTableName(ddbTableName)
      .partitionKeyName(partitionKeyName)
      .sortKeyName(sortKeyName)
      .attributeActionsOnEncrypt(attributeActionsOnEncrypt)
      .keyring(kmsKeyring)
      .allowedUnsignedAttributePrefix(unsignAttrPrefix)
      // Specifying an algorithm suite is not required, but is shown here to demonstrate how.
      // We recommend the
      // `ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384` suite, which
      // combines AES-GCM with key derivation, ECDSA signing, and key commitment. This is also
      // the default if one is not specified. For more information on supported algorithm
      // suites, see:
      //
      // https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/supported-algorithms.html
      .algorithmSuiteId(
        AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384
      )
      .build();
    tableConfigs.put(ddbTableName, config);

    // 5. Build the DynamoDB Encryption Interceptor.
    final DynamoDbEncryptionInterceptor encryptionInterceptor =
      DynamoDbEncryptionInterceptor
        .builder()
        .tableEncryptionConfigs(tableConfigs)
        .build();

    // 6. Create a new AWS SDK DynamoDb client using the DynamoDb Encryption Interceptor created
    // above.
    final DynamoDbClient ddb = DynamoDbClient
      .builder()
      .overrideConfiguration(
        ClientOverrideConfiguration
          .builder()
          .addExecutionInterceptor(encryptionInterceptor)
          .build()
      )
      .build();

    // 7. Put an item into the table using the client created above. Before the item reaches
    // DynamoDB, it will be encrypted client-side according to the configuration above.
    final Map<String, AttributeValue> item = new HashMap<>();
    item.put(
      partitionKeyName,
      AttributeValue.builder().s(partitionKeyValue).build()
    );
    item.put(sortKeyName, AttributeValue.builder().n(sortKeyValue).build());
    item.put(
      "attribute1",
      AttributeValue.builder().s("encrypt and sign me!").build()
    );
    item.put("attribute2", AttributeValue.builder().s("sign me!").build());
    item.put(":attribute3", AttributeValue.builder().s("ignore me!").build());

    final PutItemRequest putRequest = PutItemRequest
      .builder()
      .tableName(ddbTableName)
      .item(item)
      .build();

    final PutItemResponse putResponse = ddb.putItem(putRequest);

    // Demonstrate that PutItem succeeded
    assert 200 == putResponse.sdkHttpResponse().statusCode();

    // 8. Get the item back from the table using the same client. The client will decrypt the item
    // client-side on the way back, and return the original plaintext item.
    final Map<String, AttributeValue> keyToGet = new HashMap<>();
    keyToGet.put(
      partitionKeyName,
      AttributeValue.builder().s(partitionKeyValue).build()
    );
    keyToGet.put(sortKeyName, AttributeValue.builder().n(sortKeyValue).build());

    final GetItemRequest getRequest = GetItemRequest
      .builder()
      .key(keyToGet)
      .tableName(ddbTableName)
      // We request a strongly consistent read here because we read immediately after the
      // write (for demonstration). By default, DynamoDB reads are only eventually consistent,
      // so a default read right after a write may not yet see the item. Consult the docs to
      // choose the read consistency appropriate for your application:
      //
      // https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadConsistency.html
      .consistentRead(Boolean.TRUE)
      .build();

    final GetItemResponse getResponse = ddb.getItem(getRequest);

    // Demonstrate that GetItem succeeded and returned the decrypted item
    assert 200 == getResponse.sdkHttpResponse().statusCode();
    final Map<String, AttributeValue> returnedItem = getResponse.item();
    assert returnedItem.get("attribute1").s().equals("encrypt and sign me!");
  }

  public static void main(final String[] args) {
    if (args.length < 6) {
      throw new IllegalArgumentException(
        "To run this example, include the kmsKeyId as args[0], ddbTableName as args[1], " +
        "partitionKeyName as args[2], sortKeyName as args[3], partitionKeyValue as args[4], " +
        "sortKeyValue as args[5]"
      );
    }
    final String kmsKeyId = args[0];
    final String ddbTableName = args[1];
    final String partitionKeyName = args[2];
    final String sortKeyName = args[3];
    final String partitionKeyValue = args[4];
    final String sortKeyValue = args[5];
    putItemGetItem(
      kmsKeyId,
      ddbTableName,
      partitionKeyName,
      sortKeyName,
      partitionKeyValue,
      sortKeyValue
    );
  }
}
