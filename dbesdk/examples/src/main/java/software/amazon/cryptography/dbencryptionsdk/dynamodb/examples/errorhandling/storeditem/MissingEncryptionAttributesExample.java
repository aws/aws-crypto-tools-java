package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling.storeditem;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import javax.crypto.KeyGenerator;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.EncryptedDataKeyDescription;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.MalformedHeaderOrFooterException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.MissingEncryptionAttributesException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.itemencryptor.DynamoDbItemEncryptor;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * Shows what the DB-ESDK throws when it reads an item that it did not write.
 *
 * <p>The DB-ESDK adds two attributes to every item it encrypts, "aws_dbe_head" and "aws_dbe_foot".
 * An item with neither of them was not written by the DB-ESDK. By default the item encryptor
 * refuses to return it and throws {@link MissingEncryptionAttributesException}, so an unencrypted
 * item cannot pass as an encrypted one. Describing the data keys of an item with no "aws_dbe_head"
 * throws the same exception.
 *
 * <p>An item that has the attributes in the wrong form is corrupt, not unencrypted, and throws
 * {@link MalformedHeaderOrFooterException} instead: for example an "aws_dbe_head" that is not a
 * binary value, or an item with only one of the two attributes (see {@code TamperedItemExample}).
 *
 * <p>An item with neither attribute is expected while you move a table from unencrypted to
 * encrypted items: allow plaintext reads in the item encryptor's configuration until every item is
 * encrypted. Otherwise, treat the item as untrusted.
 *
 * <p>This example needs no AWS access. It uses a Raw AES keyring with a key generated in the
 * example. In practice, get the key from a key management system.
 */
public class MissingEncryptionAttributesExample {

  private static final String PARTITION_KEY = "partition_key";
  private static final String SORT_KEY = "sort_key";
  private static final String ENCRYPTED_ATTRIBUTE = "attribute1";
  private static final String SIGNED_ATTRIBUTE = "attribute2";
  private static final String HEADER_ATTRIBUTE = "aws_dbe_head";

  public static void readItemsWithoutEncryptionAttributes(
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

    decryptItemWithoutEncryptionAttributes(itemEncryptor);
    describeItemWithoutHeader();
    describeItemWhoseHeaderIsNotBinary();
  }

  private static void decryptItemWithoutEncryptionAttributes(
    DynamoDbItemEncryptor itemEncryptor
  ) {
    Map<String, AttributeValue> plaintextItem = Map.of(
      PARTITION_KEY,
      AttributeValue.fromS("MissingEncryptionAttributesExample"),
      SORT_KEY,
      AttributeValue.fromN("1"),
      ENCRYPTED_ATTRIBUTE,
      AttributeValue.fromS("never encrypted"),
      SIGNED_ATTRIBUTE,
      AttributeValue.fromS("never signed")
    );
    try {
      itemEncryptor.decryptItem(plaintextItem);
    } catch (MissingEncryptionAttributesException exception) {
      System.err.println(
        "The DB-ESDK did not write this item. If the table is being moved to encrypted items, " +
        "allow plaintext reads until every item is encrypted; otherwise do not trust it: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException("Decrypting an unencrypted item succeeded");
  }

  // Describing the data keys of an item needs the item's aws_dbe_head attribute.
  private static void describeItemWithoutHeader() {
    Map<String, AttributeValue> plaintextItem = Map.of(
      PARTITION_KEY,
      AttributeValue.fromS("MissingEncryptionAttributesExample"),
      SORT_KEY,
      AttributeValue.fromN("1")
    );
    try {
      EncryptedDataKeyDescription.fromItem(plaintextItem);
    } catch (MissingEncryptionAttributesException exception) {
      System.err.println(
        "The DB-ESDK did not write this item, so it has no data keys to describe: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "Describing the data keys of an item without aws_dbe_head succeeded"
    );
  }

  // The DB-ESDK always writes aws_dbe_head as a binary value. Here it is a string, so the item has
  // the attribute but it cannot be the DB-ESDK's header: the item is corrupt or was changed.
  private static void describeItemWhoseHeaderIsNotBinary() {
    Map<String, AttributeValue> corruptItem = Map.of(
      PARTITION_KEY,
      AttributeValue.fromS("MissingEncryptionAttributesExample"),
      SORT_KEY,
      AttributeValue.fromN("2"),
      HEADER_ATTRIBUTE,
      AttributeValue.fromS("not a binary header")
    );
    try {
      EncryptedDataKeyDescription.fromItem(corruptItem);
    } catch (MalformedHeaderOrFooterException exception) {
      System.err.println(
        "The item's aws_dbe_head attribute is not a binary value; the item is corrupt or was " +
        "changed: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "Describing the data keys of an item whose aws_dbe_head is a string succeeded"
    );
  }

  public static void main(String[] args) {
    if (args.length < 1) {
      throw new IllegalArgumentException(
        "To run this example, include the logical table name in args"
      );
    }
    readItemsWithoutEncryptionAttributes(args[0], generateAesKeyBytes());
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
