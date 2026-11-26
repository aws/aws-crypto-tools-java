package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.InvalidConfigurationException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.ValidationException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.itemencryptor.DynamoDbItemEncryptor;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.cmm.DefaultCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * Shows that a configuration needs exactly one source of data keys: a keyring or a cryptographic
 * materials manager (CMM).
 *
 * <p>The DB-ESDK checks this when you build the configuration and throws {@link
 * InvalidConfigurationException}, a {@link ValidationException}, for neither or both. Do not
 * retry: fix the configuration.
 *
 * <p>This example needs no AWS access. It uses a Raw AES keyring with a key generated in the
 * example. In practice, get the key from a key management system.
 */
public class KeyringOrCmmErrorsExample {

  private static final String PARTITION_KEY = "partition_key";
  private static final String SORT_KEY = "sort_key";

  public static void keyringOrCmmErrors(String tableName) {
    Keyring keyring = RawAesKeyring
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

    keyringAndMaterialsManagerBothSet(tableName, schema, keyring);
    neitherKeyringNorMaterialsManagerSet(tableName, schema);
  }

  // A configuration takes either a keyring or a cryptographic materials manager (CMM), not both.
  private static void keyringAndMaterialsManagerBothSet(
    String tableName,
    ItemEncryptionSchema schema,
    Keyring keyring
  ) {
    CryptographicMaterialsManager materialsManager =
      DefaultCryptographicMaterialsManager.create(keyring);
    try {
      DynamoDbItemEncryptor
        .builder()
        .logicalTableName(tableName)
        .schema(schema)
        .keyring(keyring)
        .cmm(materialsManager)
        .build();
    } catch (InvalidConfigurationException exception) {
      System.err.println(
        "Set either a keyring or a CMM, not both: " + exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "A configuration with both a keyring and a CMM was accepted"
    );
  }

  private static void neitherKeyringNorMaterialsManagerSet(
    String tableName,
    ItemEncryptionSchema schema
  ) {
    try {
      DynamoDbItemEncryptor
        .builder()
        .logicalTableName(tableName)
        .schema(schema)
        .build();
    } catch (InvalidConfigurationException exception) {
      System.err.println("Set a keyring or a CMM: " + exception.getMessage());
      return;
    }
    throw new IllegalStateException(
      "A configuration with neither a keyring nor a CMM was accepted"
    );
  }

  public static void main(String[] args) {
    if (args.length < 1) {
      throw new IllegalArgumentException(
        "To run this example, include the table name in args"
      );
    }
    keyringOrCmmErrors(args[0]);
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
