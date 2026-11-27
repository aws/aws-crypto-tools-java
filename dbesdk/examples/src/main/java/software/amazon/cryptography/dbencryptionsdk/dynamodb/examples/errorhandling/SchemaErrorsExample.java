package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.InvalidConfigurationException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.ValidationException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.itemencryptor.DynamoDbItemEncryptor;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * Shows the mistakes in an item encryption schema that the DB-ESDK rejects, and the exception it
 * throws for each.
 *
 * <p>The DB-ESDK checks a schema when you build the configuration, before it encrypts or decrypts
 * anything. For a schema that it cannot use, it throws {@link InvalidConfigurationException}, a
 * {@link ValidationException}, whose message names the setting to fix. A configuration mistake
 * does not go away on its own, so do not retry: fix the configuration.
 *
 * <p>The DB-ESDK rejects a required builder setting left unset, and a value outside its allowed
 * length or range, the same way. A {@code null} argument throws {@link ValidationException} too.
 * {@code ReservedNameErrorsExample} shows reserved attribute names.
 *
 * <p>This example needs no AWS access. It uses a Raw AES keyring with a key generated in the
 * example. In practice, get the key from a key management system.
 */
public class SchemaErrorsExample {

  private static final String PARTITION_KEY = "partition_key";
  private static final String SORT_KEY = "sort_key";
  private static final String ENCRYPTED_ATTRIBUTE = "attribute1";

  public static void buildInvalidSchemas(String tableName) {
    Keyring rawAesKeyring = RawAesKeyring
      .builder()
      .keyName("my-aes-key-name")
      .keyNamespace("my-key-namespace")
      .wrappingKey(SecretBytes.copyOf(generateAesKeyBytes()))
      .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
      .build();

    buildSchemaWithoutPartitionKeyName();
    buildSchemaThatEncryptsPartitionKey(tableName, rawAesKeyring);
  }

  // Every item has a partition key, so a schema needs its name. The DB-ESDK rejects a required
  // setting left unset when you call build().
  private static void buildSchemaWithoutPartitionKeyName() {
    try {
      ItemEncryptionSchema
        .builder()
        .sortKeyName(SORT_KEY)
        .encryptAndSign(ENCRYPTED_ATTRIBUTE)
        .build();
    } catch (InvalidConfigurationException exception) {
      System.err.println(
        "Set the partition key name: " + exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "A schema without a partition key name was built"
    );
  }

  // DynamoDB needs the partition key and sort key values in plaintext to store and find the item,
  // so the DB-ESDK signs them but never encrypts them.
  private static void buildSchemaThatEncryptsPartitionKey(
    String tableName,
    Keyring rawAesKeyring
  ) {
    try {
      ItemEncryptionSchema schemaThatEncryptsPartitionKey = ItemEncryptionSchema
        .builder()
        .partitionKeyName(PARTITION_KEY)
        .sortKeyName(SORT_KEY)
        .encryptAndSign(PARTITION_KEY, ENCRYPTED_ATTRIBUTE)
        .build();
      DynamoDbItemEncryptor
        .builder()
        .logicalTableName(tableName)
        .schema(schemaThatEncryptsPartitionKey)
        .keyring(rawAesKeyring)
        .build();
    } catch (InvalidConfigurationException exception) {
      System.err.println(
        "Do not list the partition key or sort key as encrypted: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "A schema that encrypts the partition key was accepted"
    );
  }

  public static void main(String[] args) {
    if (args.length < 1) {
      throw new IllegalArgumentException(
        "To run this example, include the table name in args"
      );
    }
    buildInvalidSchemas(args[0]);
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
