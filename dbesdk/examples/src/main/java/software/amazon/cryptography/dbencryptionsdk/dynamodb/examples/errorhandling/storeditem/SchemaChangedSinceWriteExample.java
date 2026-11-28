package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling.storeditem;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import javax.crypto.KeyGenerator;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.VerificationFailedException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.itemencryptor.DynamoDbItemEncryptor;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * Shows what the DB-ESDK throws when you read an item with a schema that no longer signs an
 * attribute that the item was signed with.
 *
 * <p>The item's signature covers every attribute that the DB-ESDK signed when it wrote the item. If
 * the schema that you read with does not sign one of them, the signature does not verify, and the
 * DB-ESDK throws {@link VerificationFailedException}. Change an attribute's action only as the
 * DB-ESDK developer guide describes in its guidance on updating your data model.
 *
 * <p>This example needs no AWS access. It uses a Raw AES keyring with a key generated in the
 * example. In practice, get the key from a key management system.
 */
public class SchemaChangedSinceWriteExample {

  private static final String PARTITION_KEY = "partition_key";
  private static final String SORT_KEY = "sort_key";
  private static final String ENCRYPTED_ATTRIBUTE = "attribute1";
  private static final String SIGNED_ATTRIBUTE = "attribute2";

  public static void decryptWithChangedSchema(
    String tableName,
    byte[] aesKeyBytes
  ) {
    Keyring rawAesKeyring = RawAesKeyring
      .builder()
      .keyName("my-aes-key-name")
      .keyNamespace("my-key-namespace")
      .wrappingKey(SecretBytes.copyOf(aesKeyBytes))
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

    Map<String, AttributeValue> encryptedItem = itemEncryptor
      .encryptItem(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS("SchemaChangedSinceWriteExample"),
          SORT_KEY,
          AttributeValue.fromN("0"),
          ENCRYPTED_ATTRIBUTE,
          AttributeValue.fromS("encrypt and sign me!"),
          SIGNED_ATTRIBUTE,
          AttributeValue.fromS("sign me!")
        )
      )
      .encryptedItem();

    decryptWithSchemaThatNoLongerSignsAttribute(
      tableName,
      rawAesKeyring,
      encryptedItem
    );
  }

  // The item was written while attribute2 was SIGN_ONLY. Here the schema makes it DO_NOTHING.
  private static void decryptWithSchemaThatNoLongerSignsAttribute(
    String tableName,
    Keyring rawAesKeyring,
    Map<String, AttributeValue> encryptedItem
  ) {
    ItemEncryptionSchema changedSchema = ItemEncryptionSchema
      .builder()
      .partitionKeyName(PARTITION_KEY)
      .sortKeyName(SORT_KEY)
      .encryptAndSign(ENCRYPTED_ATTRIBUTE)
      .doNothing(SIGNED_ATTRIBUTE)
      .build();
    DynamoDbItemEncryptor changedSchemaEncryptor = DynamoDbItemEncryptor
      .builder()
      .logicalTableName(tableName)
      .schema(changedSchema)
      .keyring(rawAesKeyring)
      .build();
    try {
      changedSchemaEncryptor.decryptItem(encryptedItem);
    } catch (VerificationFailedException exception) {
      System.err.println(
        "The schema no longer signs an attribute this item was signed with: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "Decrypting with a schema that no longer signs attribute2 succeeded"
    );
  }

  public static void main(String[] args) {
    if (args.length < 1) {
      throw new IllegalArgumentException(
        "To run this example, include the logical table name in args"
      );
    }
    decryptWithChangedSchema(args[0], generateAesKeyBytes());
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
