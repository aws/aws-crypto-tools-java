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
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.InvalidConfigurationException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.InvalidItemException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.ValidationException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.itemencryptor.DynamoDbItemEncryptor;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * Shows the names that the DB-ESDK reserves, and the exception that it throws when you use one.
 *
 * <ul>
 *   <li>Attribute names that start with "aws_dbe_" belong to the attributes that the DB-ESDK adds
 *       to each item. The DB-ESDK rejects a schema that names one when you build it, and an item
 *       that has one when you write it.
 *   <li>Names that start with "aws-crypto-" belong to the AWS encryption libraries. The logical
 *       table name, partition key name and sort key name may not start with it. The DB-ESDK checks
 *       this when it encrypts an item, not when you build the configuration.
 * </ul>
 *
 * <p>A reserved name in a configuration throws {@link InvalidConfigurationException}, and a
 * reserved name in an item throws {@link InvalidItemException}. Both are {@link
 * ValidationException}s. Do not retry: rename the attribute or table.
 *
 * <p>Running this example needs AWS credentials and a Region for the DynamoDB client in the last
 * case. Its request is rejected before it is sent, so the table does not have to exist.
 */
public class ReservedNameErrorsExample {

  private static final String PARTITION_KEY = "partition_key";
  private static final String SORT_KEY = "sort_key";
  private static final String ENCRYPTED_ATTRIBUTE = "attribute1";
  private static final String SIGNED_ATTRIBUTE = "attribute2";

  public static void reservedNameErrors(String tableName) {
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

    reservedAttributeNameInSchema(tableName, rawAesKeyring);
    reservedPrefixInLogicalTableName(schema, rawAesKeyring);

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
      reservedAttributeNameInItem(dynamoDbClient, tableName);
    }
  }

  // Attribute names that start with "aws_dbe_" are reserved for the attributes that the DB-ESDK
  // adds to each item.
  private static void reservedAttributeNameInSchema(
    String tableName,
    Keyring keyring
  ) {
    ItemEncryptionSchema schemaWithReservedName = ItemEncryptionSchema
      .builder()
      .partitionKeyName(PARTITION_KEY)
      .sortKeyName(SORT_KEY)
      .encryptAndSign("aws_dbe_secret")
      .build();
    try {
      DynamoDbItemEncryptor
        .builder()
        .logicalTableName(tableName)
        .schema(schemaWithReservedName)
        .keyring(keyring)
        .build();
    } catch (InvalidConfigurationException exception) {
      System.err.println(
        "Rename the attribute; names starting with aws_dbe_ are reserved: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "A schema with a reserved attribute name was accepted"
    );
  }

  // Names that start with "aws-crypto-" are reserved for the AWS encryption libraries. The DB-ESDK
  // encrypts every item with the logical table name, partition key name and sort key name, so none
  // of them may start with it.
  // The DB-ESDK checks this when it encrypts an item, not when you build the configuration, so the
  // item encryptor below builds and the first encryption fails.
  private static void reservedPrefixInLogicalTableName(
    ItemEncryptionSchema schema,
    Keyring keyring
  ) {
    DynamoDbItemEncryptor itemEncryptor = DynamoDbItemEncryptor
      .builder()
      .logicalTableName("aws-crypto-orders")
      .schema(schema)
      .keyring(keyring)
      .build();
    try {
      itemEncryptor.encryptItem(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS("ReservedNameErrorsExample"),
          SORT_KEY,
          AttributeValue.fromN("0"),
          ENCRYPTED_ATTRIBUTE,
          AttributeValue.fromS("encrypt and sign me!"),
          SIGNED_ATTRIBUTE,
          AttributeValue.fromS("sign me!")
        )
      );
    } catch (InvalidConfigurationException exception) {
      System.err.println(
        "Choose a logical table name and key names that do not start with aws-crypto-: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "An item was encrypted under a logical table name starting with aws-crypto-"
    );
  }

  // The DB-ESDK adds aws_dbe_head and aws_dbe_foot to each item, so an item that you write cannot
  // have an attribute whose name starts with "aws_dbe_".
  private static void reservedAttributeNameInItem(
    DynamoDbClient dynamoDbClient,
    String tableName
  ) {
    PutItemRequest request = PutItemRequest
      .builder()
      .tableName(tableName)
      .item(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS("ReservedNameErrorsExample"),
          SORT_KEY,
          AttributeValue.fromN("0"),
          ENCRYPTED_ATTRIBUTE,
          AttributeValue.fromS("encrypt and sign me!"),
          SIGNED_ATTRIBUTE,
          AttributeValue.fromS("sign me!"),
          "aws_dbe_note",
          AttributeValue.fromS("a name the DB-ESDK reserves")
        )
      )
      .build();
    try {
      dynamoDbClient.putItem(request);
    } catch (InvalidItemException exception) {
      System.err.println(
        "Rename the attribute; names starting with aws_dbe_ are reserved: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "An item with an attribute named aws_dbe_note was written"
    );
  }

  public static void main(String[] args) {
    if (args.length < 1) {
      throw new IllegalArgumentException(
        "To run this example, include the table name in args"
      );
    }
    reservedNameErrors(args[0]);
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
