package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import software.amazon.awssdk.auth.credentials.AnonymousCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.InvalidConfigurationException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * Shows the mistakes in setting up the {@link DynamoDbEncryptionInterceptor} that the DB-ESDK
 * rejects, and the exception it throws for each.
 *
 * <p>These mistakes throw {@link InvalidConfigurationException}, a {@link ValidationException}:
 *
 * <ul>
 *   <li>two tables that share a logical table name;
 *   <li>the interceptor added to a client for a service other than DynamoDB;
 *   <li>a table configuration that sets both a legacy encryptor for migration and a plaintext
 *       read or write policy. Set only one of them.
 * </ul>
 *
 * <p>Asking for the item encryptor of a table that you never configured throws plain {@link
 * ValidationException}, because the argument is wrong, not the configuration.
 *
 * <p>Do not retry: fix the configuration or the call.
 *
 * <p>This example needs no AWS access. It uses a Raw AES keyring with a key generated in the
 * example. In practice, get the key from a key management system.
 */
public class InterceptorConfigurationErrorsExample {

  private static final String PARTITION_KEY = "partition_key";
  private static final String SORT_KEY = "sort_key";
  private static final String ENCRYPTED_ATTRIBUTE = "attribute1";

  public static void interceptorConfigurationErrors(String tableName) {
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
      .build();

    sameLogicalTableNameForTwoTables(tableName, schema, rawAesKeyring);
    itemEncryptorForUnconfiguredTable(tableName, schema, rawAesKeyring);
    interceptorOnAClientThatIsNotDynamoDb(tableName, schema, rawAesKeyring);
  }

  // The DB-ESDK encrypts every item with its logical table name, so within one interceptor each
  // logical table name must belong to one table.
  private static void sameLogicalTableNameForTwoTables(
    String tableName,
    ItemEncryptionSchema schema,
    Keyring rawAesKeyring
  ) {
    DynamoDbTableEncryptionConfig firstTable = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .logicalTableName(tableName)
      .schema(schema)
      .keyring(rawAesKeyring)
      .build();
    DynamoDbTableEncryptionConfig secondTable = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName + "-copy")
      .logicalTableName(tableName)
      .schema(schema)
      .keyring(rawAesKeyring)
      .build();
    try {
      DynamoDbEncryptionInterceptor
        .builder()
        .tableConfigs(firstTable, secondTable)
        .build();
    } catch (InvalidConfigurationException exception) {
      System.err.println(
        "Give each configured table its own logical table name: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "Two tables with the same logical table name were accepted"
    );
  }

  // The interceptor has an item encryptor only for the tables that you configured.
  private static void itemEncryptorForUnconfiguredTable(
    String tableName,
    ItemEncryptionSchema schema,
    Keyring rawAesKeyring
  ) {
    DynamoDbTableEncryptionConfig tableConfig = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .schema(schema)
      .keyring(rawAesKeyring)
      .build();
    DynamoDbEncryptionInterceptor encryptionInterceptor =
      DynamoDbEncryptionInterceptor.builder().tableConfigs(tableConfig).build();
    try {
      encryptionInterceptor.itemEncryptor("UnconfiguredTable");
    } catch (ValidationException exception) {
      System.err.println(
        "Ask only for a table that you configured: " + exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "An item encryptor was returned for a table with no configuration"
    );
  }

  // The interceptor encrypts only DynamoDB requests, and rejects every request on another
  // service's client before sending it.
  // The client below has a Region and anonymous credentials so that it builds without AWS access.
  // The request never reaches AWS KMS.
  private static void interceptorOnAClientThatIsNotDynamoDb(
    String tableName,
    ItemEncryptionSchema schema,
    Keyring rawAesKeyring
  ) {
    DynamoDbTableEncryptionConfig tableConfig = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .schema(schema)
      .keyring(rawAesKeyring)
      .build();
    DynamoDbEncryptionInterceptor encryptionInterceptor =
      DynamoDbEncryptionInterceptor.builder().tableConfigs(tableConfig).build();
    try (
      KmsClient kmsClient = KmsClient
        .builder()
        .region(Region.US_WEST_2)
        .credentialsProvider(AnonymousCredentialsProvider.create())
        .overrideConfiguration(overrides ->
          overrides.addExecutionInterceptor(encryptionInterceptor)
        )
        .build()
    ) {
      kmsClient.listKeys();
    } catch (InvalidConfigurationException exception) {
      // The client was built with the wrong interceptor, so no request on it can succeed. Fix it
      // by registering the encryption interceptor only on a DynamoDbClient.
      System.err.println(
        "Register the encryption interceptor only on a DynamoDbClient: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "A KMS request through the encryption interceptor was sent"
    );
  }

  public static void main(String[] args) {
    if (args.length < 1) {
      throw new IllegalArgumentException(
        "To run this example, include the table name in args"
      );
    }
    interceptorConfigurationErrors(args[0]);
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
