package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.KeyGenerator;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.EncryptedDataKeyDescription;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.MalformedHeaderOrFooterException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.VerificationFailedException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.itemencryptor.DynamoDbItemEncryptor;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * Shows what the DB-ESDK throws when a stored item was changed after the DB-ESDK wrote it.
 *
 * <p>When the DB-ESDK encrypts an item, it signs every attribute that is encrypted or signed, and
 * stores the signature and the information needed to decrypt the item in two extra attributes,
 * "aws_dbe_head" and "aws_dbe_foot". When it decrypts the item, it checks all of that again. Each
 * case below changes an encrypted item the way a bug or an attacker could:
 *
 * <ul>
 *   <li>{@link VerificationFailedException}: the item failed verification. A signed or
 *       encrypted attribute, or a key attribute, was changed. Treat the item as untrusted. A Raw
 *       AES keyring with the item's key namespace and name but a different key also fails this
 *       way: it cannot tell a wrong key from a changed item.
 *   <li>{@link MalformedHeaderOrFooterException}: the "aws_dbe_head" or "aws_dbe_foot" attribute
 *       is not in a form that the DB-ESDK can read, or only one of the two is present. The item is
 *       corrupt or was changed. An item with neither is shown in {@code
 *       MissingEncryptionAttributesExample}.
 * </ul>
 *
 * <p>A check for whether an item was changed should catch both {@link
 * VerificationFailedException} and {@link MalformedHeaderOrFooterException}. They are separate
 * classes, and neither is a subclass of the other. With an AWS KMS keyring, AWS KMS checks the key
 * attributes when it decrypts the item's data key, so a changed key attribute is instead a {@code
 * ServiceException} whose {@code awsErrorCode()} is {@code InvalidCiphertextException}.
 * {@code TamperedItemReadThroughClientExample} shows the same failure on a read through the
 * encrypted DynamoDB client.
 *
 * <p>This example needs no AWS access. It uses a Raw AES keyring with a key generated in the
 * example. In practice, get the key from a key management system.
 */
public class TamperedItemExample {

  private static final String PARTITION_KEY = "partition_key";
  private static final String SORT_KEY = "sort_key";
  private static final String ENCRYPTED_ATTRIBUTE = "attribute1";
  private static final String SIGNED_ATTRIBUTE = "attribute2";
  private static final String HEADER_ATTRIBUTE = "aws_dbe_head";

  public static void tamperedItems(String tableName, byte[] aesKeyBytes) {
    Keyring keyring = RawAesKeyring
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
      .keyring(keyring)
      .build();

    Map<String, AttributeValue> encryptedItem = itemEncryptor
      .encryptItem(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS("TamperedItemExample"),
          SORT_KEY,
          AttributeValue.fromN("0"),
          ENCRYPTED_ATTRIBUTE,
          AttributeValue.fromS("encrypt and sign me!"),
          SIGNED_ATTRIBUTE,
          AttributeValue.fromS("sign me!")
        )
      )
      .encryptedItem();

    changedSignedAttribute(itemEncryptor, encryptedItem);
    changedEncryptedAttribute(itemEncryptor, encryptedItem);
    changedKeyAttribute(itemEncryptor, encryptedItem);

    // The same item with aws_dbe_head cut to half its length.
    byte[] header = encryptedItem.get(HEADER_ATTRIBUTE).b().asByteArray();
    Map<String, AttributeValue> truncatedHeaderItem = new HashMap<>(
      encryptedItem
    );
    truncatedHeaderItem.put(
      HEADER_ATTRIBUTE,
      AttributeValue.fromB(
        SdkBytes.fromByteArray(Arrays.copyOf(header, header.length / 2))
      )
    );
    truncatedHeader(itemEncryptor, truncatedHeaderItem);
    describeTruncatedHeader(truncatedHeaderItem);
  }

  // A SIGN_ONLY attribute is stored as plaintext, but the item's signature covers it.
  private static void changedSignedAttribute(
    DynamoDbItemEncryptor itemEncryptor,
    Map<String, AttributeValue> encryptedItem
  ) {
    Map<String, AttributeValue> changedItem = new HashMap<>(encryptedItem);
    changedItem.put(SIGNED_ATTRIBUTE, AttributeValue.fromS("changed!"));
    try {
      itemEncryptor.decryptItem(changedItem);
    } catch (VerificationFailedException exception) {
      System.err.println(
        "A signed attribute was changed; do not trust this item: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "Decrypting an item with a changed signed attribute succeeded"
    );
  }

  // An ENCRYPT_AND_SIGN attribute is stored encrypted and is covered by the signature.
  private static void changedEncryptedAttribute(
    DynamoDbItemEncryptor itemEncryptor,
    Map<String, AttributeValue> encryptedItem
  ) {
    byte[] ciphertext = encryptedItem
      .get(ENCRYPTED_ATTRIBUTE)
      .b()
      .asByteArray();
    ciphertext[ciphertext.length - 1] ^= 1;
    Map<String, AttributeValue> changedItem = new HashMap<>(encryptedItem);
    changedItem.put(
      ENCRYPTED_ATTRIBUTE,
      AttributeValue.fromB(SdkBytes.fromByteArray(ciphertext))
    );
    try {
      itemEncryptor.decryptItem(changedItem);
    } catch (VerificationFailedException exception) {
      System.err.println(
        "An encrypted attribute was changed; do not trust this item: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "Decrypting an item with a changed encrypted attribute succeeded"
    );
  }

  // The keyring binds the item's data key to the partition key and sort key values, so an item
  // copied to a different key no longer decrypts.
  // With an AWS KMS keyring, AWS KMS makes this check, and the DB-ESDK throws a ServiceException
  // whose awsErrorCode() is InvalidCiphertextException instead.
  private static void changedKeyAttribute(
    DynamoDbItemEncryptor itemEncryptor,
    Map<String, AttributeValue> encryptedItem
  ) {
    Map<String, AttributeValue> changedItem = new HashMap<>(encryptedItem);
    changedItem.put(PARTITION_KEY, AttributeValue.fromS("AnotherPartition"));
    try {
      itemEncryptor.decryptItem(changedItem);
    } catch (VerificationFailedException exception) {
      System.err.println(
        "The item's key was changed, or the item was copied to another key; do not trust it: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "Decrypting an item with a changed partition key succeeded"
    );
  }

  private static void truncatedHeader(
    DynamoDbItemEncryptor itemEncryptor,
    Map<String, AttributeValue> truncatedHeaderItem
  ) {
    try {
      itemEncryptor.decryptItem(truncatedHeaderItem);
    } catch (MalformedHeaderOrFooterException exception) {
      System.err.println(
        "The item's aws_dbe_head attribute cannot be read; the item is corrupt or was changed: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "Decrypting an item with a truncated header succeeded"
    );
  }

  // Describing an item's data keys reads aws_dbe_head too.
  private static void describeTruncatedHeader(
    Map<String, AttributeValue> truncatedHeaderItem
  ) {
    try {
      EncryptedDataKeyDescription.fromItem(truncatedHeaderItem);
    } catch (MalformedHeaderOrFooterException exception) {
      System.err.println(
        "The item's aws_dbe_head attribute cannot be read: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "Describing the data keys of an item with a truncated header succeeded"
    );
  }

  public static void main(String[] args) {
    if (args.length < 1) {
      throw new IllegalArgumentException(
        "To run this example, include the logical table name in args"
      );
    }
    tamperedItems(args[0], generateAesKeyBytes());
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
