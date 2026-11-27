package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import javax.crypto.KeyGenerator;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ExecuteStatementRequest;
import software.amazon.awssdk.services.dynamodb.model.ExpectedAttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;
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
 * Shows the DynamoDB requests that the DB-ESDK refuses to send for an encrypted table because it
 * cannot rewrite them.
 *
 * <p>The DB-ESDK can protect only the requests that it can rewrite. It rejects the rest before
 * sending them and throws {@link UnsupportedRequestException}, a {@link ValidationException}.
 * Change the request; a retry gets the same result.
 *
 * <p>The rejected requests include:
 *
 * <ul>
 *   <li>PartiQL ({@code ExecuteStatement}, {@code BatchExecuteStatement}, {@code
 *       ExecuteTransaction}) on an encrypted table.
 *   <li>The legacy request parameters {@code Expected}, {@code AttributeUpdates}, {@code
 *       AttributesToGet}, {@code KeyConditions}, {@code QueryFilter}, {@code ScanFilter} and
 *       {@code ConditionalOperator}. Use expressions instead.
 *   <li>A {@code TransactWriteItems} entry that sets none of {@code Put}, {@code Update}, {@code
 *       Delete} and {@code ConditionCheck}.
 * </ul>
 *
 * <p>Running this example needs AWS credentials and a Region for the DynamoDB client. Every request
 * below is rejected before it is sent, so the table does not have to exist.
 */
public class UnsupportedRequestErrorsExample {

  private static final String PARTITION_KEY = "partition_key";
  private static final String SORT_KEY = "sort_key";
  private static final String ENCRYPTED_ATTRIBUTE = "attribute1";
  private static final String SIGNED_ATTRIBUTE = "attribute2";

  public static void sendUnsupportedRequests(String tableName) {
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
      executePartiqlStatement(dynamoDbClient, tableName);
      putItemWithLegacyExpected(dynamoDbClient, tableName);
      transactWriteEntryWithNoOperation(dynamoDbClient);
    }
  }

  private static void executePartiqlStatement(
    DynamoDbClient dynamoDbClient,
    String tableName
  ) {
    ExecuteStatementRequest request = ExecuteStatementRequest
      .builder()
      .statement("SELECT * FROM \"" + tableName + "\"")
      .build();
    try {
      dynamoDbClient.executeStatement(request);
    } catch (UnsupportedRequestException exception) {
      System.err.println(
        "Use GetItem, Query or Scan on an encrypted table, not PartiQL: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "A PartiQL statement on an encrypted table was sent"
    );
  }

  private static void putItemWithLegacyExpected(
    DynamoDbClient dynamoDbClient,
    String tableName
  ) {
    PutItemRequest request = PutItemRequest
      .builder()
      .tableName(tableName)
      .item(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS("UnsupportedRequestErrorsExample"),
          SORT_KEY,
          AttributeValue.fromN("0"),
          ENCRYPTED_ATTRIBUTE,
          AttributeValue.fromS("encrypt and sign me!"),
          SIGNED_ATTRIBUTE,
          AttributeValue.fromS("sign me!")
        )
      )
      .expected(
        Map.of(
          PARTITION_KEY,
          ExpectedAttributeValue.builder().exists(false).build()
        )
      )
      .build();
    try {
      dynamoDbClient.putItem(request);
    } catch (UnsupportedRequestException exception) {
      System.err.println(
        "Replace Expected with a condition expression: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "A PutItem request with the legacy Expected parameter was sent"
    );
  }

  // Each entry in a transaction must say what it does to an item. The DB-ESDK checks this for the
  // whole request, before it looks at any table name.
  private static void transactWriteEntryWithNoOperation(
    DynamoDbClient dynamoDbClient
  ) {
    TransactWriteItemsRequest request = TransactWriteItemsRequest
      .builder()
      .transactItems(TransactWriteItem.builder().build())
      .build();
    try {
      dynamoDbClient.transactWriteItems(request);
    } catch (UnsupportedRequestException exception) {
      System.err.println(
        "Set Put, Update, Delete or ConditionCheck on every transaction entry: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "A transaction entry with no operation was sent"
    );
  }

  public static void main(String[] args) {
    if (args.length < 1) {
      throw new IllegalArgumentException(
        "To run this example, include the table name in args"
      );
    }
    sendUnsupportedRequests(args[0]);
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
