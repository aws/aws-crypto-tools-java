package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling.requestanditem;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import javax.crypto.KeyGenerator;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.UnsupportedRequestException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * Shows the condition and update expressions that the DB-ESDK rejects on an encrypted table.
 *
 * <p>DynamoDB cannot compare encrypted values, and changing a signed attribute in place would
 * break the item's signature. So before it sends the request, the DB-ESDK throws {@link
 * UnsupportedRequestException} for:
 *
 * <ul>
 *   <li>a condition expression that reads an encrypted attribute;
 *   <li>an update expression that changes a signed attribute. Write the whole item with {@code
 *       PutItem} instead.
 * </ul>
 *
 * <p>The DB-ESDK also checks an {@code UpdateItem} response. If the response would return signed
 * attributes without the rest of the item, the DB-ESDK cannot verify them and throws {@link
 * UnsupportedRequestException}. DynamoDB has already applied that update, so do not retry it. Ask
 * for {@code ReturnValue.ALL_NEW} or {@code ALL_OLD} when you need signed attributes back.
 *
 * <p>{@link UnsupportedRequestException} is a {@link ValidationException}, so a {@code catch} of
 * {@link ValidationException} catches it too.
 *
 * <p>Running this example needs AWS credentials and a Region for the DynamoDB client. Every request
 * below is rejected before it is sent, so the table does not have to exist.
 */
public class ExpressionErrorsExample {

  private static final String PARTITION_KEY = "partition_key";
  private static final String SORT_KEY = "sort_key";
  private static final String ENCRYPTED_ATTRIBUTE = "attribute1";
  private static final String SIGNED_ATTRIBUTE = "attribute2";

  public static void sendUnsupportedExpressions(String tableName) {
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
      .encryptAndSign(ENCRYPTED_ATTRIBUTE)
      .signOnly(SIGNED_ATTRIBUTE)
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
      putItemWithConditionOnEncryptedAttribute(dynamoDbClient, tableName);
      updateSignedAttribute(dynamoDbClient, tableName);
    }
  }

  private static void putItemWithConditionOnEncryptedAttribute(
    DynamoDbClient dynamoDbClient,
    String tableName
  ) {
    PutItemRequest request = PutItemRequest
      .builder()
      .tableName(tableName)
      .item(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS("ExpressionErrorsExample"),
          SORT_KEY,
          AttributeValue.fromN("0"),
          ENCRYPTED_ATTRIBUTE,
          AttributeValue.fromS("encrypt and sign me!"),
          SIGNED_ATTRIBUTE,
          AttributeValue.fromS("sign me!")
        )
      )
      .conditionExpression(ENCRYPTED_ATTRIBUTE + " = :value")
      .expressionAttributeValues(
        Map.of(":value", AttributeValue.fromS("encrypt and sign me!"))
      )
      .build();
    try {
      dynamoDbClient.putItem(request);
    } catch (UnsupportedRequestException exception) {
      System.err.println(
        "Do not use an encrypted attribute in a condition expression: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "A condition expression on an encrypted attribute was sent"
    );
  }

  private static void updateSignedAttribute(
    DynamoDbClient dynamoDbClient,
    String tableName
  ) {
    UpdateItemRequest request = UpdateItemRequest
      .builder()
      .tableName(tableName)
      .key(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS("ExpressionErrorsExample"),
          SORT_KEY,
          AttributeValue.fromN("0")
        )
      )
      .updateExpression("SET " + SIGNED_ATTRIBUTE + " = :value")
      .expressionAttributeValues(
        Map.of(":value", AttributeValue.fromS("changed!"))
      )
      .build();
    try {
      dynamoDbClient.updateItem(request);
    } catch (UnsupportedRequestException exception) {
      System.err.println(
        "Write the whole item with PutItem to change a signed attribute: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "An update expression on a signed attribute was sent"
    );
  }

  public static void main(String[] args) {
    if (args.length < 1) {
      throw new IllegalArgumentException(
        "To run this example, include the table name in args"
      );
    }
    sendUnsupportedExpressions(args[0]);
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
