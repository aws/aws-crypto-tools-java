package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import javax.crypto.KeyGenerator;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.EncryptedDataKeyDescription;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.DynamoDbEncryptionException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.itemencryptor.DynamoDbItemEncryptor;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.MultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * Shows what the DB-ESDK throws when you read an item with a keyring that cannot decrypt it.
 *
 * <p>An encrypted item stores its data key once for each key that it was encrypted for, as an
 * "encrypted data key". To decrypt the item, the keyring must be able to decrypt one of them.
 *
 * <ul>
 *   <li>When the keyring has no key that any of the item's encrypted data keys is for, the
 *       DB-ESDK throws {@link NoMatchingDataKeyException}. {@code encryptedDataKeys()} says which
 *       keys the item was encrypted for, so you can find the keyring that can read it. It never
 *       contains key material.
 *   <li>When decrypting takes several attempts and every one fails, for example a multi keyring
 *       trying each of its keyrings, the DB-ESDK throws one exception. Its kind is that of the
 *       attempt that you are most likely to act on. If any attempt is worth retrying, the
 *       exception is retryable, so check {@code isRetryable()} first.
 *       <p>For diagnosis, the Material Providers Library (MPL) exception holds every attempt as a
 *       suppressed exception, and stack traces print them. The MPL exception is two levels down
 *       the cause chain: the DB-ESDK exception's cause is the StructuredEncryption exception,
 *       whose cause is the MPL exception.
 * </ul>
 *
 * <p>This example needs no AWS access. It uses Raw AES keyrings with keys generated in the example.
 * In practice, get the keys from a key management system.
 */
public class NoMatchingDataKeyExample {

  private static final String PARTITION_KEY = "partition_key";
  private static final String SORT_KEY = "sort_key";
  private static final String ENCRYPTED_ATTRIBUTE = "attribute1";
  // The writer and reader use different key namespaces, so the key provider ID that
  // NoMatchingDataKeyException reports tells them apart.
  private static final String WRITER_NAMESPACE = "writer-key-namespace";
  private static final String WRITER_KEY_NAME = "writer-key";
  private static final String READER_NAMESPACE = "reader-key-namespace";
  private static final String READER_KEY_NAME = "reader-key";

  public static void decryptWithKeyringsThatCannotDecrypt(String tableName) {
    ItemEncryptionSchema schema = ItemEncryptionSchema
      .builder()
      .partitionKeyName(PARTITION_KEY)
      .sortKeyName(SORT_KEY)
      .encryptAndSign(ENCRYPTED_ATTRIBUTE)
      .build();

    Keyring writerKeyring = RawAesKeyring
      .builder()
      .keyName(WRITER_KEY_NAME)
      .keyNamespace(WRITER_NAMESPACE)
      .wrappingKey(SecretBytes.copyOf(generateAesKeyBytes()))
      .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
      .build();
    DynamoDbItemEncryptor writer = DynamoDbItemEncryptor
      .builder()
      .logicalTableName(tableName)
      .schema(schema)
      .keyring(writerKeyring)
      .build();
    Map<String, AttributeValue> plaintextItem = Map.of(
      PARTITION_KEY,
      AttributeValue.fromS("NoMatchingDataKeyExample"),
      SORT_KEY,
      AttributeValue.fromN("0"),
      ENCRYPTED_ATTRIBUTE,
      AttributeValue.fromS("encrypt and sign me!")
    );
    Map<String, AttributeValue> encryptedItem = writer
      .encryptItem(plaintextItem)
      .encryptedItem();

    // The reader's keyring holds only the reader's key.
    Keyring readerKeyring = RawAesKeyring
      .builder()
      .keyName(READER_KEY_NAME)
      .keyNamespace(READER_NAMESPACE)
      .wrappingKey(SecretBytes.copyOf(generateAesKeyBytes()))
      .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
      .build();
    DynamoDbItemEncryptor reader = DynamoDbItemEncryptor
      .builder()
      .logicalTableName(tableName)
      .schema(schema)
      .keyring(readerKeyring)
      .build();
    readWithKeyringForAnotherKey(reader, encryptedItem);

    // This keyring has the writer's key namespace and name, but different key bytes.
    Keyring wrongBytesKeyring = RawAesKeyring
      .builder()
      .keyName(WRITER_KEY_NAME)
      .keyNamespace(WRITER_NAMESPACE)
      .wrappingKey(SecretBytes.copyOf(generateAesKeyBytes()))
      .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
      .build();
    Keyring multiKeyring = MultiKeyring
      .builder()
      .generator(readerKeyring)
      .childKeyrings(wrongBytesKeyring)
      .build();
    DynamoDbItemEncryptor multiKeyringReader = DynamoDbItemEncryptor
      .builder()
      .logicalTableName(tableName)
      .schema(schema)
      .keyring(multiKeyring)
      .build();
    readWithMultiKeyringWhoseKeysAllFail(multiKeyringReader, encryptedItem);
  }

  // The item was encrypted only for the writer's key.
  private static void readWithKeyringForAnotherKey(
    DynamoDbItemEncryptor reader,
    Map<String, AttributeValue> encryptedItem
  ) {
    try {
      reader.decryptItem(encryptedItem);
    } catch (NoMatchingDataKeyException exception) {
      for (EncryptedDataKeyDescription encryptedDataKey : exception.encryptedDataKeys()) {
        // For a raw keyring, the key provider ID is the keyring's key namespace and
        // keyProviderInfo() is null. For an AWS KMS keyring, keyProviderInfo() is the KMS key
        // ARN; for a hierarchical keyring, it is the branch key ID.
        System.err.println(
          "The item was encrypted for key provider " +
          encryptedDataKey.keyProviderId() +
          "; read it with a keyring for that key"
        );
      }
      return;
    }
    throw new IllegalStateException(
      "Decrypting with a keyring for another key succeeded"
    );
  }

  // A multi keyring tries its generator first, then each child keyring. Here neither can decrypt
  // the item:
  // - the generator is for another key, so it finds no data key to decrypt;
  // - the child has the right key name but the wrong key bytes, so AES-GCM decryption of the data
  //   key fails.
  // Neither failure is retryable, and a key that fails to decrypt is more actionable than a
  // missing data key, so the DB-ESDK throws a VerificationFailedException.
  private static void readWithMultiKeyringWhoseKeysAllFail(
    DynamoDbItemEncryptor reader,
    Map<String, AttributeValue> encryptedItem
  ) {
    try {
      reader.decryptItem(encryptedItem);
    } catch (DynamoDbEncryptionException exception) {
      if (exception.isRetryable()) {
        System.err.println(
          "At least one keyring might succeed if you retry later: " +
          exception.getMessage()
        );
        return;
      }
      System.err.println(
        "Decrypting failed (" +
        exception.getClass().getName() +
        "): " +
        exception.getMessage()
      );
      // Every keyring's failure, in the order tried, for diagnosis. A logged stack trace prints
      // them too. They are on the MPL exception: the cause of the StructuredEncryption exception,
      // which is the cause of the exception caught here.
      Throwable structuredEncryptionFailure = exception.getCause();
      Throwable materialProvidersFailure = structuredEncryptionFailure == null
        ? null
        : structuredEncryptionFailure.getCause();
      if (materialProvidersFailure != null) {
        for (Throwable attempt : materialProvidersFailure.getSuppressed()) {
          System.err.println(
            "  attempt failed (" +
            attempt.getClass().getName() +
            "): " +
            attempt.getMessage()
          );
        }
      }
      return;
    }
    throw new IllegalStateException(
      "Decrypting with keyrings for the wrong keys succeeded"
    );
  }

  public static void main(String[] args) {
    if (args.length < 1) {
      throw new IllegalArgumentException(
        "To run this example, include the logical table name in args"
      );
    }
    decryptWithKeyringsThatCannotDecrypt(args[0]);
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
