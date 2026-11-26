package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import javax.crypto.KeyGenerator;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.InvalidItemException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * Shows the items that the DB-ESDK refuses to write because it cannot encrypt or sign them.
 *
 * <p>The DB-ESDK checks each item before sending it, and throws {@link InvalidItemException} for an
 * item:
 *
 * <ul>
 *   <li>with an attribute that the schema gives no action;
 *   <li>with values nested more than 32 levels deep;
 *   <li>without an attribute that the schema marks {@code signAndIncludeInEncryptionContext};
 *   <li>with a number attribute that is not a valid number.
 * </ul>
 *
 * <p>Change the item; a retry gets the same result. {@code MissingPartitionOrSortKeyExample} shows
 * an item without its partition key or sort key.
 *
 * <p>{@link InvalidItemException} is a {@link ValidationException}, so a {@code catch} of {@link
 * ValidationException} catches it too. Catch {@link InvalidItemException} to skip one bad item and
 * go on with the others.
 *
 * <p>Running this example needs AWS credentials and a Region for the DynamoDB client. Every request
 * below is rejected before it is sent, so the table does not have to exist.
 */
public class ItemContentErrorsExample {

  private static final String PARTITION_KEY = "partition_key";
  private static final String SORT_KEY = "sort_key";
  private static final String ENCRYPTED_ATTRIBUTE = "attribute1";
  private static final String SIGNED_ATTRIBUTE = "attribute2";

  public static void itemContentErrors(String tableName) {
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
      attributeWithNoAction(dynamoDbClient, tableName);
      valueNestedTooDeep(dynamoDbClient, tableName);
      numberThatIsNotANumber(dynamoDbClient, tableName);
    }
  }

  // The schema lists every attribute that this table may have. "attribute3" is not in it.
  private static void attributeWithNoAction(
    DynamoDbClient dynamoDbClient,
    String tableName
  ) {
    PutItemRequest request = PutItemRequest
      .builder()
      .tableName(tableName)
      .item(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS("ItemContentErrorsExample"),
          SORT_KEY,
          AttributeValue.fromN("0"),
          ENCRYPTED_ATTRIBUTE,
          AttributeValue.fromS("encrypt and sign me!"),
          SIGNED_ATTRIBUTE,
          AttributeValue.fromS("sign me!"),
          "attribute3",
          AttributeValue.fromS("no action configured for me")
        )
      )
      .build();
    try {
      dynamoDbClient.putItem(request);
    } catch (InvalidItemException exception) {
      System.err.println(
        "Give every attribute an action in the schema, or a name that starts with a " +
        "do-nothing prefix: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "An item with an attribute that has no action was written"
    );
  }

  private static void valueNestedTooDeep(
    DynamoDbClient dynamoDbClient,
    String tableName
  ) {
    AttributeValue nestedValue = AttributeValue.fromS("deep");
    for (int levels = 0; levels < 40; levels++) {
      nestedValue = AttributeValue.fromM(Map.of("nested", nestedValue));
    }
    PutItemRequest request = PutItemRequest
      .builder()
      .tableName(tableName)
      .item(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS("ItemContentErrorsExample"),
          SORT_KEY,
          AttributeValue.fromN("0"),
          ENCRYPTED_ATTRIBUTE,
          nestedValue,
          SIGNED_ATTRIBUTE,
          AttributeValue.fromS("sign me!")
        )
      )
      .build();
    try {
      dynamoDbClient.putItem(request);
    } catch (InvalidItemException exception) {
      System.err.println(
        "Nest maps and lists no more than 32 levels deep: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "An item nested 40 levels deep was written"
    );
  }

  // DynamoDB numbers are sent as strings, and the AWS SDK does not check them. The DB-ESDK must
  // read a number to sign or encrypt it, so it rejects one that is not a valid number.
  private static void numberThatIsNotANumber(
    DynamoDbClient dynamoDbClient,
    String tableName
  ) {
    PutItemRequest request = PutItemRequest
      .builder()
      .tableName(tableName)
      .item(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS("ItemContentErrorsExample"),
          SORT_KEY,
          AttributeValue.fromN("0"),
          ENCRYPTED_ATTRIBUTE,
          AttributeValue.fromN("1.2.3"),
          SIGNED_ATTRIBUTE,
          AttributeValue.fromS("sign me!")
        )
      )
      .build();
    try {
      dynamoDbClient.putItem(request);
    } catch (InvalidItemException exception) {
      System.err.println(
        "Write number attributes as valid decimal numbers: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "An item with an invalid number was written"
    );
  }

  public static void main(String[] args) {
    if (args.length < 1) {
      throw new IllegalArgumentException(
        "To run this example, include the table name in args"
      );
    }
    itemContentErrors(args[0]);
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
