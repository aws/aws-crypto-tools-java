package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
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
import software.amazon.cryptography.dbencryptionsdk.dynamodb.itemencryptor.DynamoDbItemEncryptor;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * Shows that the DB-ESDK needs an item's partition key and sort key both to encrypt and to decrypt
 * it.
 *
 * <p>The DB-ESDK encrypts each item with its key values. Writing an item without them, and
 * decrypting an item that has lost them, both throw {@link InvalidItemException}, a {@link
 * ValidationException}. Pass the whole item.
 *
 * <p>Running this example needs AWS credentials and a Region for the DynamoDB client. The write
 * below is rejected before it is sent, so the table does not have to exist.
 */
public class MissingPartitionOrSortKeyExample {

  private static final String PARTITION_KEY = "partition_key";
  private static final String SORT_KEY = "sort_key";
  private static final String ENCRYPTED_ATTRIBUTE = "attribute1";
  private static final String SIGNED_ATTRIBUTE = "attribute2";

  public static void missingPartitionOrSortKey(String tableName) {
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

    DynamoDbItemEncryptor itemEncryptor = DynamoDbItemEncryptor
      .builder()
      .logicalTableName(tableName)
      .schema(schema)
      .keyring(rawAesKeyring)
      .build();
    Map<String, AttributeValue> plaintextItem = Map.of(
      PARTITION_KEY,
      AttributeValue.fromS("MissingPartitionOrSortKeyExample"),
      SORT_KEY,
      AttributeValue.fromN("0"),
      ENCRYPTED_ATTRIBUTE,
      AttributeValue.fromS("encrypt and sign me!"),
      SIGNED_ATTRIBUTE,
      AttributeValue.fromS("sign me!")
    );
    Map<String, AttributeValue> encryptedItem = itemEncryptor
      .encryptItem(plaintextItem)
      .encryptedItem();
    decryptItemWithoutSortKey(itemEncryptor, encryptedItem);

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
      writeItemWithoutSortKey(dynamoDbClient, tableName);
    }
  }

  private static void writeItemWithoutSortKey(
    DynamoDbClient dynamoDbClient,
    String tableName
  ) {
    PutItemRequest request = PutItemRequest
      .builder()
      .tableName(tableName)
      .item(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS("MissingPartitionOrSortKeyExample"),
          ENCRYPTED_ATTRIBUTE,
          AttributeValue.fromS("encrypt and sign me!"),
          SIGNED_ATTRIBUTE,
          AttributeValue.fromS("sign me!")
        )
      )
      .build();
    try {
      dynamoDbClient.putItem(request);
    } catch (InvalidItemException exception) {
      System.err.println(
        "Include the partition key and sort key in every item: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException("An item without its sort key was written");
  }

  // This happens when you pass part of an item, for example one read with a projection expression
  // that leaves out the sort key.
  private static void decryptItemWithoutSortKey(
    DynamoDbItemEncryptor itemEncryptor,
    Map<String, AttributeValue> encryptedItem
  ) {
    Map<String, AttributeValue> partialItem = new HashMap<>(encryptedItem);
    partialItem.remove(SORT_KEY);
    try {
      itemEncryptor.decryptItem(partialItem);
    } catch (InvalidItemException exception) {
      System.err.println(
        "Pass the whole stored item, with its partition key and sort key: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "Decrypting an item without its sort key succeeded"
    );
  }

  public static void main(String[] args) {
    if (args.length < 1) {
      throw new IllegalArgumentException(
        "To run this example, include the table name in args"
      );
    }
    missingPartitionOrSortKey(args[0]);
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
