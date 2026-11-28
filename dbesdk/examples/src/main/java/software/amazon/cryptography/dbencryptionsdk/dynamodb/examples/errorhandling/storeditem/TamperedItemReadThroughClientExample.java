package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling.storeditem;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.KeyGenerator;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.ExampleUtils;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.VerificationFailedException;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * Shows that a read through the encrypted DynamoDB client throws the same exceptions as the item
 * encryptor in {@code TamperedItemExample}.
 *
 * <p>Here a client that does not decrypt changes the item's encrypted attribute. Reading the item
 * back through the encrypted client then throws {@link VerificationFailedException}.
 *
 * <p>Running this example needs AWS credentials and a DynamoDB table with partition key
 * "partition_key" (S) and sort key "sort_key" (N). It writes one encrypted item to the table. It
 * uses a Raw AES keyring with a key generated in the example; in practice, get the key from a key
 * management system.
 */
public class TamperedItemReadThroughClientExample {

  private static final String PARTITION_KEY = "partition_key";
  private static final String SORT_KEY = "sort_key";
  private static final String ENCRYPTED_ATTRIBUTE = "attribute1";

  public static void readTamperedItemThroughClient(String tableName) {
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
        .build();
      DynamoDbClient plaintextClient = DynamoDbClient.create()
    ) {
      getItemChangedAfterWrite(dynamoDbClient, plaintextClient, tableName);
    }
  }

  private static void getItemChangedAfterWrite(
    DynamoDbClient dynamoDbClient,
    DynamoDbClient plaintextClient,
    String tableName
  ) {
    // A partition key unique to this run, so a concurrent run cannot write this item between the
    // change below and the read.
    String partitionValue = ExampleUtils.uniquePartitionKey("ChangedItem");
    PutItemRequest write = PutItemRequest
      .builder()
      .tableName(tableName)
      .item(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS(partitionValue),
          SORT_KEY,
          AttributeValue.fromN("0"),
          ENCRYPTED_ATTRIBUTE,
          AttributeValue.fromS("encrypt and sign me!")
        )
      )
      .build();
    Map<String, AttributeValue> key = Map.of(
      PARTITION_KEY,
      AttributeValue.fromS(partitionValue),
      SORT_KEY,
      AttributeValue.fromN("0")
    );
    GetItemRequest read = GetItemRequest
      .builder()
      .tableName(tableName)
      .key(key)
      .consistentRead(true)
      .build();
    try {
      dynamoDbClient.putItem(write);

      // Flip one bit of the stored ciphertext with the client that does not decrypt.
      Map<String, AttributeValue> storedItem = new HashMap<>(
        plaintextClient.getItem(read).item()
      );
      byte[] ciphertext = storedItem.get(ENCRYPTED_ATTRIBUTE).b().asByteArray();
      ciphertext[ciphertext.length - 1] ^= 1;
      storedItem.put(
        ENCRYPTED_ATTRIBUTE,
        AttributeValue.fromB(SdkBytes.fromByteArray(ciphertext))
      );
      PutItemRequest overwrite = PutItemRequest
        .builder()
        .tableName(tableName)
        .item(storedItem)
        .build();
      plaintextClient.putItem(overwrite);

      dynamoDbClient.getItem(read);
    } catch (VerificationFailedException exception) {
      System.err.println(
        "The stored item failed verification: it was changed after it was written. Do not " +
        "trust its contents: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException("Reading a changed item succeeded");
  }

  public static void main(String[] args) {
    if (args.length < 1) {
      throw new IllegalArgumentException(
        "To run this example, include the table name in args"
      );
    }
    readTamperedItemThroughClient(args[0]);
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
