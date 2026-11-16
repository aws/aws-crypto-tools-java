package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.keyring;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.ExampleUtils;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.PaddingScheme;
import software.amazon.cryptography.materialproviders.keyrings.RawRsaKeyring;

/**
 * This example sets up DynamoDB Encryption for the AWS SDK client using the raw RSA Keyring. This
 * keyring uses an RSA key pair to encrypt and decrypt records. This keyring accepts PEM encodings of
 * the key pair as UTF-8 interpreted bytes. The client uses the public key to encrypt items it adds to
 * the table and uses the private key to decrypt existing table items it retrieves.
 *
 * <p>This example loads a key pair from PEM files with paths defined in
 *  - EXAMPLE_RSA_PRIVATE_KEY_FILENAME
 *  - EXAMPLE_RSA_PUBLIC_KEY_FILENAME
 * If you do not provide these files, running this example through this class' main method
 * will generate these files for you. These files will be generated in the directory where
 * the example is run.
 * In practice, users of this library should not generate new key pairs like this, and should
 * instead retrieve an existing key from a secure key management system (e.g. an HSM).
 * You may also provide your own key pair by placing PEM files in the directory where the
 * example is run or modifying the paths in the code below. These files must be valid PEM
 * encodings of the key pair as UTF-8 encoded bytes. If you do provide your own key pair,
 * or if a key pair already exists, this class' main method will not generate a new key pair.
 *
 * <p>This example loads a key pair from disk, encrypts a test item, and puts the encrypted item to the
 * provided DynamoDB table. Then, it gets the item from the table and decrypts it.
 *
 * <p>Running this example requires access to the DynamoDB Table whose name is provided in CLI arguments. This
 * table must be configured with the following primary key configuration:
 *   - Partition key is named "partition_key" with type (S)
 *   - Sort key is named "sort_key" with type (N)
 */
public class RawRsaKeyringExample {

  private static final String EXAMPLE_RSA_PRIVATE_KEY_FILENAME =
    "RawRsaKeyringExamplePrivateKey.pem";
  private static final String EXAMPLE_RSA_PUBLIC_KEY_FILENAME =
    "RawRsaKeyringExamplePublicKey.pem";

  public static void putAndGetItem(String tableName) {
    // 1. Load key pair from UTF-8 encoded PEM files.
    //    You may provide your own PEM files to use here.
    //    If you do not, the main method in this class will generate PEM
    //    files for example use. Do not use these files for any other purpose.
    byte[] publicKeyUtf8EncodedBytes;
    try {
      publicKeyUtf8EncodedBytes =
        Files.readAllBytes(Path.of(EXAMPLE_RSA_PUBLIC_KEY_FILENAME));
    } catch (IOException exception) {
      throw new UncheckedIOException(
        "IOException while reading public key from file",
        exception
      );
    }

    byte[] privateKeyUtf8EncodedBytes;
    try {
      privateKeyUtf8EncodedBytes =
        Files.readAllBytes(Path.of(EXAMPLE_RSA_PRIVATE_KEY_FILENAME));
    } catch (IOException exception) {
      throw new UncheckedIOException(
        "IOException while reading private key from file",
        exception
      );
    }

    // 2. Create the keyring.
    //    The DynamoDB encryption client uses this to encrypt and decrypt items.
    Keyring rawRsaKeyring = RawRsaKeyring
      .builder()
      .keyName("my-rsa-key-name")
      .keyNamespace("my-key-namespace")
      .paddingScheme(PaddingScheme.OAEP_SHA256_MGF1)
      .publicKey(publicKeyUtf8EncodedBytes)
      .privateKey(SecretBytes.copyOf(privateKeyUtf8EncodedBytes))
      .build();

    // 3. Decide how each attribute of your items is protected. BasicPutGetExample
    //    explains each action (encryptAndSign, signOnly, signAndIncludeInEncryptionContext,
    //    doNothing), and why the partition and sort keys get none.
    //    Every attribute you write must either have an action or start with the prefix set in the
    //    next step; writing an item with any other attribute fails.

    // 4. Decide which attributes are left out of the signature. Two separate settings do this. They
    //    do different jobs, and you can use either one, both, or neither:
    //
    //    - doNothingPrefix(":") is a naming rule. Every attribute whose name starts with this text
    //      is treated as doNothing, without being listed anywhere. It lets you add new unsigned
    //      attributes later just by naming them with the prefix, with no configuration change. Pick
    //      the prefix before you write any items, and do not change it afterwards.
    //
    //    - doNothing("name", ...) lists specific attributes by name, for unsigned attributes whose
    //      names do not start with the prefix. Never remove a name from this list while items that
    //      have that attribute may still be in the table, or reading those items fails. To add a
    //      name, first update the configuration on every reader, and only then start writing the
    //      new attribute.
    //
    //    This example sets the prefix ":" so that unsigned attributes can be added later. The items
    //    it writes do not have any yet.

    // Build the schema from the choices above.
    ItemEncryptionSchema schema = ItemEncryptionSchema
      .builder()
      .partitionKeyName("partition_key")
      .sortKeyName("sort_key")
      .encryptAndSign("sensitive_data")
      .doNothingPrefix(":")
      .build();

    // 5. Create the DynamoDB Encryption configuration for the table we will be writing to.
    DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .schema(schema)
      .keyring(rawRsaKeyring)
      .build();

    // 6. Create the DynamoDB Encryption Interceptor
    DynamoDbEncryptionInterceptor encryptionInterceptor =
      DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();

    // 7. Create a new AWS SDK DynamoDB client using the DynamoDB Encryption Interceptor above
    try (
      DynamoDbClient dynamoDbClient = DynamoDbClient
        .builder()
        .overrideConfiguration(overrides ->
          overrides.addExecutionInterceptor(encryptionInterceptor)
        )
        .build()
    ) {
      // 8. Put an item into our table using the above client.
      //    Before the item gets sent to DynamoDB, it will be encrypted
      //    client-side, according to our configuration.
      Map<String, AttributeValue> item = Map.of(
        "partition_key",
        AttributeValue.fromS(
          ExampleUtils.uniquePartitionKey("rawRsaKeyringItem")
        ),
        "sort_key",
        AttributeValue.fromN("0"),
        "sensitive_data",
        AttributeValue.fromS("encrypt and sign me!")
      );
      PutItemRequest putRequest = PutItemRequest
        .builder()
        .tableName(tableName)
        .item(item)
        .build();

      dynamoDbClient.putItem(putRequest);

      // 9. Get the item back from our table using the same client.
      //    The client will decrypt the item client-side, and return
      //    back the original item.
      Map<String, AttributeValue> keyToGet = Map.of(
        "partition_key",
        AttributeValue.fromS(
          ExampleUtils.uniquePartitionKey("rawRsaKeyringItem")
        ),
        "sort_key",
        AttributeValue.fromN("0")
      );
      GetItemRequest getRequest = GetItemRequest
        .builder()
        .key(keyToGet)
        .tableName(tableName)
        .build();

      GetItemResponse getResponse = dynamoDbClient.getItem(getRequest);

      // Demonstrate that GetItem succeeded and returned the decrypted item
      Map<String, AttributeValue> returnedItem = getResponse.item();
      assert returnedItem
        .get("sensitive_data")
        .s()
        .equals("encrypt and sign me!");
    }
  }

  public static void main(String[] args) {
    if (args.length < 1) {
      throw new IllegalArgumentException(
        "To run this example, include the table name in args"
      );
    }
    String tableName = args[0];

    // You may provide your own RSA key pair in the files located at
    //  - EXAMPLE_RSA_PRIVATE_KEY_FILENAME
    //  - EXAMPLE_RSA_PUBLIC_KEY_FILENAME
    // If these files are not present, this will generate a pair for you
    if (shouldGenerateNewRsaKeyPair()) {
      generateRsaKeyPair();
    }

    putAndGetItem(tableName);
  }

  private static boolean shouldGenerateNewRsaKeyPair() {
    // Check if a key pair already exists
    Path privateKeyFile = Path.of(EXAMPLE_RSA_PRIVATE_KEY_FILENAME);
    Path publicKeyFile = Path.of(EXAMPLE_RSA_PUBLIC_KEY_FILENAME);

    // If a key pair already exists: do not overwrite existing key pair
    if (Files.exists(privateKeyFile) && Files.exists(publicKeyFile)) {
      return false;
    }

    // If only one file is present: throw exception
    if (Files.exists(privateKeyFile) && !Files.exists(publicKeyFile)) {
      throw new IllegalStateException(
        "Missing public key file at " + EXAMPLE_RSA_PUBLIC_KEY_FILENAME
      );
    }
    if (!Files.exists(privateKeyFile) && Files.exists(publicKeyFile)) {
      throw new IllegalStateException(
        "Missing private key file at " + EXAMPLE_RSA_PRIVATE_KEY_FILENAME
      );
    }

    // If neither file is present, generate a new key pair
    return true;
  }

  private static void generateRsaKeyPair() {
    // Safety check: Validate neither file is present
    Path privateKeyFile = Path.of(EXAMPLE_RSA_PRIVATE_KEY_FILENAME);
    Path publicKeyFile = Path.of(EXAMPLE_RSA_PUBLIC_KEY_FILENAME);
    if (Files.exists(privateKeyFile) || Files.exists(publicKeyFile)) {
      throw new IllegalStateException(
        "generateRsaKeyPair will not overwrite existing PEM files"
      );
    }

    // This code will generate a new RSA key pair for example use.
    // The public and private key will be written to the files:
    //  - public: EXAMPLE_RSA_PUBLIC_KEY_FILENAME
    //  - private: EXAMPLE_RSA_PRIVATE_KEY_FILENAME
    // This example uses BouncyCastle's KeyPairGenerator to generate the key pair.
    // In practice, you should not generate this in your code, and should instead
    // retrieve this key from a secure key management system (e.g. HSM)
    // This key is created here for example purposes only.
    KeyPairGenerator rsaKeyGenerator;
    try {
      rsaKeyGenerator = KeyPairGenerator.getInstance("RSA");
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException(
        "This JVM does not support RSA key generation",
        exception
      );
    }
    rsaKeyGenerator.initialize(2048, new SecureRandom());
    KeyPair keyPair = rsaKeyGenerator.generateKeyPair();

    StringWriter privateKeyStringWriter = new StringWriter();
    try (
      PemWriter privateKeyPemWriter = new PemWriter(privateKeyStringWriter)
    ) {
      privateKeyPemWriter.writeObject(
        new PemObject("PRIVATE KEY", keyPair.getPrivate().getEncoded())
      );
    } catch (IOException exception) {
      throw new UncheckedIOException(
        "IOException while writing private key PEM",
        exception
      );
    }

    // Write UTF-8 encoded PEM file
    try {
      Files.writeString(
        Path.of(EXAMPLE_RSA_PRIVATE_KEY_FILENAME),
        privateKeyStringWriter.toString()
      );
    } catch (IOException exception) {
      throw new UncheckedIOException(
        "IOException while writing private key file",
        exception
      );
    }

    StringWriter publicKeyStringWriter = new StringWriter();
    try (PemWriter publicKeyPemWriter = new PemWriter(publicKeyStringWriter)) {
      publicKeyPemWriter.writeObject(
        new PemObject("PUBLIC KEY", keyPair.getPublic().getEncoded())
      );
    } catch (IOException exception) {
      throw new UncheckedIOException(
        "IOException while writing public key PEM",
        exception
      );
    }
    try {
      Files.writeString(
        Path.of(EXAMPLE_RSA_PUBLIC_KEY_FILENAME),
        publicKeyStringWriter.toString()
      );
    } catch (IOException exception) {
      throw new UncheckedIOException(
        "IOException while writing public key file",
        exception
      );
    }
  }
}
