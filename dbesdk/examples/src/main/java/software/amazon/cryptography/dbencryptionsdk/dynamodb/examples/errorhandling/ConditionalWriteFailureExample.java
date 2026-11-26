package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import javax.crypto.KeyGenerator;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * Shows that an error that DynamoDB returns for your request reaches you unchanged.
 *
 * <p>A failed condition, a transaction conflict and the other errors that DynamoDB returns arrive
 * as the AWS SDK's {@code DynamoDbException} subclasses, the same as without the DB-ESDK. Here the
 * second write is conditional on the item not existing yet.
 *
 * <p>Running this example needs AWS credentials and a DynamoDB table with partition key
 * "partition_key" (S) and sort key "sort_key" (N). It writes one encrypted item to the table. It
 * uses a Raw AES keyring with a key generated in the example; in practice, get the key from a key
 * management system.
 */
public class ConditionalWriteFailureExample {

  private static final String PARTITION_KEY = "partition_key";
  private static final String SORT_KEY = "sort_key";

  public static void conditionalWriteFailure(String tableName) {
    Keyring rawAesKeyring = RawAesKeyring
      .builder()
      .keyName("my-aes-key-name")
      .keyNamespace("my-key-namespace")
      .wrappingKey(SecretBytes.copyOf(generateAesKeyBytes()))
      .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
      .build();
    ItemEncryptionSchema schema = ItemEncryptionSchema
      .builder()
      .partitionKeyName(PARTITION_KEY)
      .sortKeyName(SORT_KEY)
      .encryptAndSign("attribute1")
      .build();
    DynamoDbTableEncryptionConfig tableConfig = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .schema(schema)
      .keyring(rawAesKeyring)
      .build();
    DynamoDbEncryptionInterceptor encryptionInterceptor =
      DynamoDbEncryptionInterceptor.builder().tableConfigs(tableConfig).build();

    try (
      DynamoDbClient dynamoDbClient = DynamoDbClient
        .builder()
        .overrideConfiguration(overrides ->
          overrides.addExecutionInterceptor(encryptionInterceptor)
        )
        .build()
    ) {
      failedConditionInDynamoDb(dynamoDbClient, tableName);
    }
  }

  private static void failedConditionInDynamoDb(
    DynamoDbClient dynamoDbClient,
    String tableName
  ) {
    PutItemRequest write = PutItemRequest
      .builder()
      .tableName(tableName)
      .item(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS("ConditionalWriteFailureExample"),
          SORT_KEY,
          AttributeValue.fromN("0"),
          "attribute1",
          AttributeValue.fromS("encrypt and sign me!")
        )
      )
      .build();
    PutItemRequest writeIfAbsent = write
      .toBuilder()
      .conditionExpression("attribute_not_exists(" + PARTITION_KEY + ")")
      .build();
    try {
      dynamoDbClient.putItem(write);
      dynamoDbClient.putItem(writeIfAbsent);
    } catch (ConditionalCheckFailedException exception) {
      System.err.println(
        "The item already exists: " + exception.awsErrorDetails().errorCode()
      );
      return;
    }
    throw new IllegalStateException(
      "A conditional write of an existing item succeeded"
    );
  }

  public static void main(String[] args) {
    if (args.length < 1) {
      throw new IllegalArgumentException(
        "To run this example, include the table name in args"
      );
    }
    conditionalWriteFailure(args[0]);
  }

  private static byte[] generateAesKeyBytes() {
    // This example uses the JCA KeyGenerator to generate the key bytes. In practice, do not
    // generate this key in your code; get it from a key management system, such as an HSM.
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
    return aesKeyGenerator.generateKey().getEncoded();
  }
}
