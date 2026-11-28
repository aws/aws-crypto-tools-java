package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.keyring;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
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
import software.amazon.cryptography.materialproviders.keyrings.EcdhCurveSpec;
import software.amazon.cryptography.materialproviders.keyrings.RawEcdhKeyAgreementScheme;
import software.amazon.cryptography.materialproviders.keyrings.RawEcdhKeyring;

/**
 * These examples set up DynamoDB Encryption for the AWS SDK client using the raw ECDH Keyring. This
 * keyring, depending on its KeyAgreement scheme, takes in the sender's ECC private key, and the
 * recipient's ECC Public Key to derive a shared secret. The keyring uses the shared secret to derive
 * a data key to protect the data keys that encrypt and decrypt DynamoDB table items.
 *
 * <p>Running these examples require access to the DynamoDB Table whose name is provided in CLI arguments.
 * This table must be configured with the following primary key configuration:
 *   - Partition key is named "partition_key" with type (S)
 *   - Sort key is named "sort_key" with type (N)
 */
public class RawEcdhKeyringExample {

  public static final String EXAMPLE_ECC_PRIVATE_KEY_FILENAME_SENDER =
    "RawEcdhKeyringExamplePrivateKeySender.pem";
  public static final String EXAMPLE_ECC_PRIVATE_KEY_FILENAME_RECIPIENT =
    "RawEcdhKeyringExamplePrivateKeyRecipient.pem";
  public static final String EXAMPLE_ECC_PUBLIC_KEY_FILENAME_RECIPIENT =
    "RawEcdhKeyringExamplePublicKeyRecipient.pem";

  /**
   * This example takes in the sender's private key as a UTF8 PEM-encoded (PKCS #8 PrivateKeyInfo
   * structures) located at the file location defined in EXAMPLE_ECC_PRIVATE_KEY_FILENAME_SENDER, the
   * recipient's public key as a UTF8 PEM-encoded X.509 public key, also known as
   * SubjectPublicKeyInfo (SPKI), located at the file location defined in
   * EXAMPLE_ECC_PUBLIC_KEY_FILENAME_RECIPIENT, and the Curve Specification where the keys lie.
   *
   * <p>This example encrypts a test item using the provided ECC keys and puts the encrypted item to the
   * provided DynamoDB table. Then, it gets the item from the table and decrypts it.
   *
   * <p>This example creates a RawECDH keyring with the RawPrivateKeyToStaticPublicKey key agreement
   * scheme. For more information on this configuration see:
   * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-raw-ecdh-keyring.html#raw-ecdh-RawPrivateKeyToStaticPublicKey
   *
   * <p>On encrypt, the shared secret is derived from the sender's private key and the recipient's
   * public key. On decrypt, the shared secret is derived from the sender's private key and the
   * recipient's public key; however, on decrypt the recipient can construct a keyring such that the
   * shared secret is calculated with the recipient's private key and the sender's public key. In
   * both scenarios the shared secret will be the same.
   */
  public static void putAndGetItem(String tableName, EcdhCurveSpec curveSpec) {
    // Load key pair from UTF-8 encoded PEM files.
    // You may provide your own PEM files to use here. If you provide this, it MUST
    // be a key on curve P256.
    // If you do not, the main method in this class will generate PEM
    // files for example use. Do not use these files for any other purpose.
    byte[] senderPrivateKeyPem;
    try {
      senderPrivateKeyPem =
        Files.readAllBytes(Path.of(EXAMPLE_ECC_PRIVATE_KEY_FILENAME_SENDER));
    } catch (IOException exception) {
      throw new UncheckedIOException(
        "IOException while reading the private key from file",
        exception
      );
    }

    byte[] recipientPublicKeyDer;
    try {
      PemObject pemObject;
      try (
        PemReader pemReader = new PemReader(
          Files.newBufferedReader(
            Path.of(EXAMPLE_ECC_PUBLIC_KEY_FILENAME_RECIPIENT)
          )
        )
      ) {
        pemObject = pemReader.readPemObject();
      }
      if (pemObject == null) {
        throw new IllegalArgumentException(
          EXAMPLE_ECC_PUBLIC_KEY_FILENAME_RECIPIENT +
          " does not hold a PEM-encoded public key"
        );
      }
      byte[] content = pemObject.getContent();
      SubjectPublicKeyInfo subjectPublicKeyInfo =
        SubjectPublicKeyInfo.getInstance(content);
      X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(
        subjectPublicKeyInfo.getEncoded()
      );
      if (Security.getProvider("BC") == null) {
        Security.addProvider(new BouncyCastleProvider());
      }
      KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
      PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);
      recipientPublicKeyDer = publicKey.getEncoded();
    } catch (IOException exception) {
      throw new UncheckedIOException(
        "IOException while reading the public key from file",
        exception
      );
    } catch (
      NoSuchAlgorithmException
      | NoSuchProviderException
      | InvalidKeySpecException exception
    ) {
      throw new IllegalStateException(
        "Could not load the ECC public key",
        exception
      );
    }

    // Create the keyring. This keyring uses static sender and recipient keys. This configuration
    // calls for both of the keys to be on the same curve (P256, P384, P521). On encrypt, the shared
    // secret is derived from the sender's private key and the recipient's public key. For this
    // example, on decrypt, the shared secret is derived from the sender's private key and the
    // recipient's public key; however, on decrypt the recipient can construct a keyring such that
    // the shared secret is calculated with the recipient's private key and the sender's public key.
    // In both scenarios the shared secret will be the same. The DynamoDB encryption client uses
    // this to encrypt and decrypt items.
    Keyring rawEcdhKeyring = RawEcdhKeyring
      .builder()
      .curveSpec(curveSpec)
      .keyAgreementScheme(
        RawEcdhKeyAgreementScheme
          .rawPrivateKeyToStaticPublicKey()
          .senderStaticPrivateKey(SecretBytes.copyOf(senderPrivateKeyPem))
          .recipientPublicKey(recipientPublicKeyDer)
          .build()
      )
      .build();

    putAndGetItemWithKeyring(rawEcdhKeyring, tableName);
  }

  /**
   * This example takes in the recipient's public key located at
   * EXAMPLE_ECC_PUBLIC_KEY_FILENAME_RECIPIENT as a UTF8 PEM-encoded X.509 public key, and the Curve
   * Specification where the key lies.
   *
   * <p>This example creates a RawECDH keyring with the EphemeralPrivateKeyToStaticPublicKey key
   * agreement scheme. This configuration will always create a new key pair as the sender key pair
   * for the key agreement operation. The ephemeral configuration can only encrypt data and CANNOT
   * decrypt messages. For more information on this configuration see:
   * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-raw-ecdh-keyring.html#raw-ecdh-EphemeralPrivateKeyToStaticPublicKey
   */
  public static void putItemWithEphemeralKeyring(
    String tableName,
    EcdhCurveSpec ecdhCurveSpec
  ) {
    // Load public key from UTF-8 encoded PEM files into a DER encoded public key.
    // You may provide your own PEM files to use here. If you provide this, it MUST
    // be a key on curve P256.
    // If you do not, the main method in this class will generate PEM
    // files for example use. Do not use these files for any other purpose.
    byte[] recipientPublicKeyDer;
    try {
      PemObject pemObject;
      try (
        PemReader pemReader = new PemReader(
          Files.newBufferedReader(
            Path.of(EXAMPLE_ECC_PUBLIC_KEY_FILENAME_RECIPIENT)
          )
        )
      ) {
        pemObject = pemReader.readPemObject();
      }
      if (pemObject == null) {
        throw new IllegalArgumentException(
          EXAMPLE_ECC_PUBLIC_KEY_FILENAME_RECIPIENT +
          " does not hold a PEM-encoded public key"
        );
      }
      byte[] content = pemObject.getContent();
      SubjectPublicKeyInfo subjectPublicKeyInfo =
        SubjectPublicKeyInfo.getInstance(content);
      X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(
        subjectPublicKeyInfo.getEncoded()
      );
      if (Security.getProvider("BC") == null) {
        Security.addProvider(new BouncyCastleProvider());
      }
      KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
      PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);
      recipientPublicKeyDer = publicKey.getEncoded();
    } catch (IOException exception) {
      throw new UncheckedIOException(
        "IOException while reading the public key from file",
        exception
      );
    } catch (
      NoSuchAlgorithmException
      | NoSuchProviderException
      | InvalidKeySpecException exception
    ) {
      throw new IllegalStateException(
        "Could not load the ECC public key",
        exception
      );
    }

    // Create the keyring.
    // This keyring uses an ephemeral configuration. This configuration will always create a new
    // key pair as the sender key pair for the key agreement operation. The ephemeral configuration can only
    // encrypt data and CANNOT decrypt messages.
    // The DynamoDB encryption client uses this to encrypt items.
    Keyring rawEcdhKeyring = RawEcdhKeyring
      .builder()
      .curveSpec(ecdhCurveSpec)
      .keyAgreementScheme(
        RawEcdhKeyAgreementScheme
          .ephemeralPrivateKeyToStaticPublicKey()
          .recipientPublicKey(recipientPublicKeyDer)
          .build()
      )
      .build();

    // A raw ecdh keyring with Ephemeral configuration cannot decrypt data since the key pair
    // used as the sender is ephemeral. This means that at decrypt time it does not have
    // the private key that corresponds to the public key that is stored on the message.
    putItemWithKeyring(rawEcdhKeyring, tableName);
  }

  /**
   * This example takes in the recipient's private key located at
   * EXAMPLE_ECC_PRIVATE_KEY_FILENAME_RECIPIENT as a UTF8 PEM-encoded (PKCS #8 PrivateKeyInfo
   * structures) private key, and the Curve Specification where the key lies.
   *
   * <p>This example creates a RawECDH keyring with the PublicKeyDiscovery key agreement scheme. This
   * scheme is only available on decrypt. For more information on this configuration see:
   * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-raw-ecdh-keyring.html#raw-ecdh-PublicKeyDiscovery
   */
  public static void getItemWithDiscoveryKeyring(
    String tableName,
    EcdhCurveSpec ecdhCurveSpec
  ) {
    // Load key pair from UTF-8 encoded PEM files.
    // You may provide your own PEM files to use here. If you provide this, it MUST
    // be a key on curve P256.
    // If you do not, the main method in this class will generate PEM
    // files for example use. Do not use these files for any other purpose.
    byte[] recipientPrivateKeyPem;
    try {
      recipientPrivateKeyPem =
        Files.readAllBytes(Path.of(EXAMPLE_ECC_PRIVATE_KEY_FILENAME_RECIPIENT));
    } catch (IOException exception) {
      throw new UncheckedIOException(
        "IOException while reading the private key from file",
        exception
      );
    }

    // Create the keyring. This keyring uses a discovery configuration. This configuration will
    // check on decrypt if it is meant to decrypt the message by checking if the configured public
    // key is stored on the message. The discovery configuration can only decrypt messages and
    // CANNOT encrypt messages. The DynamoDB encryption client uses this to decrypt items.
    Keyring rawEcdhKeyring = RawEcdhKeyring
      .builder()
      .curveSpec(ecdhCurveSpec)
      .keyAgreementScheme(
        RawEcdhKeyAgreementScheme
          .publicKeyDiscovery()
          .recipientStaticPrivateKey(SecretBytes.copyOf(recipientPrivateKeyPem))
          .build()
      )
      .build();

    // A raw ecdh keyring with discovery configuration cannot encrypt data since the keyring
    // looks for its configured public key on the message.
    getItemWithKeyring(rawEcdhKeyring, tableName);
  }

  private static void putAndGetItemWithKeyring(
    Keyring rawEcdhKeyring,
    String tableName
  ) {
    // Decide how each attribute of your items is protected. BasicPutGetExample
    // explains each action (encryptAndSign, signOnly, signAndIncludeInEncryptionContext,
    // doNothing), and why the partition and sort keys get none.
    // Every attribute you write must either have an action or start with the prefix set below;
    // writing an item with any other attribute fails.

    // Decide which attributes are left out of the signature. Two separate settings do this. They do
    // different jobs, and you can use either one, both, or neither:
    //
    // - doNothingPrefix(":") is a naming rule. Every attribute whose name starts with this text is
    //   treated as doNothing, without being listed anywhere. It lets you add new unsigned
    //   attributes later just by naming them with the prefix, with no configuration change. Pick
    //   the prefix before you write any items, and do not change it afterwards.
    //
    // - doNothing("name", ...) lists specific attributes by name, for unsigned attributes whose
    //   names do not start with the prefix. Never remove a name from this list while items that
    //   have that attribute may still be in the table, or reading those items fails. To add a name,
    //   first update the configuration on every reader, and only then start writing the new
    //   attribute.
    //
    // This example sets the prefix ":" so that unsigned attributes can be added later. The items it
    // writes do not have any yet.

    // Build the schema from the choices above.
    ItemEncryptionSchema schema = ItemEncryptionSchema
      .builder()
      .partitionKeyName("partition_key")
      .sortKeyName("sort_key")
      .encryptAndSign("sensitive_data")
      .doNothingPrefix(":")
      .build();

    // Create the DynamoDB Encryption configuration for the table we will be writing to.
    DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .schema(schema)
      .keyring(rawEcdhKeyring)
      .build();

    // Create the DynamoDB Encryption Interceptor
    DynamoDbEncryptionInterceptor encryptionInterceptor =
      DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();

    // Create a new AWS SDK DynamoDB client using the DynamoDB Encryption Interceptor above
    try (
      DynamoDbClient dynamoDbClient = DynamoDbClient
        .builder()
        .overrideConfiguration(overrides ->
          overrides.addExecutionInterceptor(encryptionInterceptor)
        )
        .build()
    ) {
      // Put an item into our table using the above client.
      // Before the item gets sent to DynamoDB, it will be encrypted
      // client-side, according to our configuration.
      Map<String, AttributeValue> item = Map.of(
        "partition_key",
        AttributeValue.fromS(
          ExampleUtils.uniquePartitionKey("rawEcdhKeyringItem")
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

      // Get the item back from our table using the same client.
      // The client will decrypt the item client-side, and return
      // back the original item.
      Map<String, AttributeValue> keyToGet = Map.of(
        "partition_key",
        AttributeValue.fromS(
          ExampleUtils.uniquePartitionKey("rawEcdhKeyringItem")
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

  private static void putItemWithKeyring(
    Keyring rawEcdhKeyring,
    String tableName
  ) {
    // Decide how each attribute of your items is protected. BasicPutGetExample
    // explains each action (encryptAndSign, signOnly, signAndIncludeInEncryptionContext,
    // doNothing), and why the partition and sort keys get none.
    // Every attribute you write must either have an action or start with the prefix set below;
    // writing an item with any other attribute fails.

    // Decide which attributes are left out of the signature. Two separate settings do this. They do
    // different jobs, and you can use either one, both, or neither:
    //
    // - doNothingPrefix(":") is a naming rule. Every attribute whose name starts with this text is
    //   treated as doNothing, without being listed anywhere. It lets you add new unsigned
    //   attributes later just by naming them with the prefix, with no configuration change. Pick
    //   the prefix before you write any items, and do not change it afterwards.
    //
    // - doNothing("name", ...) lists specific attributes by name, for unsigned attributes whose
    //   names do not start with the prefix. Never remove a name from this list while items that
    //   have that attribute may still be in the table, or reading those items fails. To add a name,
    //   first update the configuration on every reader, and only then start writing the new
    //   attribute.
    //
    // This example sets the prefix ":" so that unsigned attributes can be added later. The items it
    // writes do not have any yet.

    // Build the schema from the choices above.
    ItemEncryptionSchema schema = ItemEncryptionSchema
      .builder()
      .partitionKeyName("partition_key")
      .sortKeyName("sort_key")
      .encryptAndSign("sensitive_data")
      .doNothingPrefix(":")
      .build();

    // Create the DynamoDB Encryption configuration for the table we will be writing to.
    DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .schema(schema)
      .keyring(rawEcdhKeyring)
      .build();

    // Create the DynamoDB Encryption Interceptor
    DynamoDbEncryptionInterceptor encryptionInterceptor =
      DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();

    // Create a new AWS SDK DynamoDB client using the DynamoDB Encryption Interceptor above
    try (
      DynamoDbClient dynamoDbClient = DynamoDbClient
        .builder()
        .overrideConfiguration(overrides ->
          overrides.addExecutionInterceptor(encryptionInterceptor)
        )
        .build()
    ) {
      // Put an item into our table using the above client.
      // Before the item gets sent to DynamoDB, it will be encrypted
      // client-side, according to our configuration.
      Map<String, AttributeValue> item = Map.of(
        "partition_key",
        AttributeValue.fromS(
          ExampleUtils.uniquePartitionKey("rawEcdhKeyringItem")
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
    }
  }

  private static void getItemWithKeyring(
    Keyring rawEcdhKeyring,
    String tableName
  ) {
    // Decide how each attribute of your items is protected. BasicPutGetExample
    // explains each action (encryptAndSign, signOnly, signAndIncludeInEncryptionContext,
    // doNothing), and why the partition and sort keys get none.
    // Every attribute you write must either have an action or start with the prefix set below;
    // writing an item with any other attribute fails.

    // Decide which attributes are left out of the signature. Two separate settings do this. They do
    // different jobs, and you can use either one, both, or neither:
    //
    // - doNothingPrefix(":") is a naming rule. Every attribute whose name starts with this text is
    //   treated as doNothing, without being listed anywhere. It lets you add new unsigned
    //   attributes later just by naming them with the prefix, with no configuration change. Pick
    //   the prefix before you write any items, and do not change it afterwards.
    //
    // - doNothing("name", ...) lists specific attributes by name, for unsigned attributes whose
    //   names do not start with the prefix. Never remove a name from this list while items that
    //   have that attribute may still be in the table, or reading those items fails. To add a name,
    //   first update the configuration on every reader, and only then start writing the new
    //   attribute.
    //
    // This example sets the prefix ":" so that unsigned attributes can be added later. The items it
    // writes do not have any yet.

    // Build the schema from the choices above.
    ItemEncryptionSchema schema = ItemEncryptionSchema
      .builder()
      .partitionKeyName("partition_key")
      .sortKeyName("sort_key")
      .encryptAndSign("sensitive_data")
      .doNothingPrefix(":")
      .build();

    // Create the DynamoDB Encryption configuration for the table we will be writing to.
    DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .schema(schema)
      .keyring(rawEcdhKeyring)
      .build();

    // Create the DynamoDB Encryption Interceptor
    DynamoDbEncryptionInterceptor encryptionInterceptor =
      DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();

    // Create a new AWS SDK DynamoDB client using the DynamoDB Encryption Interceptor above
    try (
      DynamoDbClient dynamoDbClient = DynamoDbClient
        .builder()
        .overrideConfiguration(overrides ->
          overrides.addExecutionInterceptor(encryptionInterceptor)
        )
        .build()
    ) {
      // Get the item back from our table using the same client.
      // The client will decrypt the item client-side, and return
      // back the original item.
      Map<String, AttributeValue> keyToGet = Map.of(
        "partition_key",
        AttributeValue.fromS(
          ExampleUtils.uniquePartitionKey("rawEcdhKeyringItem")
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

  // To run this example, provide the DynamoDB table name as args[0].
  // The ECC keys are read from:
  // - EXAMPLE_ECC_PRIVATE_KEY_FILENAME_SENDER
  // - EXAMPLE_ECC_PRIVATE_KEY_FILENAME_RECIPIENT
  // - EXAMPLE_ECC_PUBLIC_KEY_FILENAME_RECIPIENT
  // Supply your own P256 key pairs in those files, or let this method generate them for you.
  public static void main(String[] args) {
    if (args.length < 1) {
      throw new IllegalArgumentException(
        "To run this example, include the table name in args"
      );
    }
    String tableName = args[0];

    if (shouldGenerateNewEccKeyPairs()) {
      generateEccKeyPairs();
    }

    // Every keyring below must be told which curve its keys lie on, and will fail if the keys lie
    // on a different one. The generated key pairs are on P256.
    EcdhCurveSpec curveSpec = EcdhCurveSpec.ECC_NIST_P256;

    // Static sender private key plus static recipient public key: this configuration can both
    // encrypt and decrypt, so it writes an item and reads it back.
    putAndGetItem(tableName, curveSpec);

    // The ephemeral configuration discards its sender key pair after the write, so it can only
    // encrypt. It writes over the item above, leaving a record that only the holder of the
    // recipient private key can read.
    putItemWithEphemeralKeyring(tableName, curveSpec);

    // The discovery configuration can only decrypt, so it has to follow a write. It reads the
    // record the ephemeral write just left, deriving the shared secret from the recipient private
    // key and the sender public key carried on the record.
    getItemWithDiscoveryKeyring(tableName, curveSpec);
  }

  private static boolean shouldGenerateNewEccKeyPairs() {
    Path privateKeyFileSender = Path.of(
      EXAMPLE_ECC_PRIVATE_KEY_FILENAME_SENDER
    );
    Path privateKeyFileRecipient = Path.of(
      EXAMPLE_ECC_PRIVATE_KEY_FILENAME_RECIPIENT
    );
    Path publicKeyFileRecipient = Path.of(
      EXAMPLE_ECC_PUBLIC_KEY_FILENAME_RECIPIENT
    );

    // If keys already exist: do not overwrite existing keys
    return (
      !Files.exists(privateKeyFileSender) &&
      !Files.exists(publicKeyFileRecipient) &&
      !Files.exists(privateKeyFileRecipient)
    );
  }

  private static void generateEccKeyPairs() {
    Path privateKeyFileSender = Path.of(
      EXAMPLE_ECC_PRIVATE_KEY_FILENAME_SENDER
    );
    Path privateKeyFileRecipient = Path.of(
      EXAMPLE_ECC_PRIVATE_KEY_FILENAME_RECIPIENT
    );
    Path publicKeyFileRecipient = Path.of(
      EXAMPLE_ECC_PUBLIC_KEY_FILENAME_RECIPIENT
    );

    if (
      Files.exists(privateKeyFileSender) ||
      Files.exists(publicKeyFileRecipient) ||
      Files.exists(privateKeyFileRecipient)
    ) {
      throw new IllegalStateException(
        "generateEccKeyPairs will not overwrite existing PEM files"
      );
    }

    // This code will generate new ECC key pairs for example use.
    // The keys will be written to the files:
    //  - private_sender: EXAMPLE_ECC_PRIVATE_KEY_FILENAME_SENDER
    //  - private_recipient: EXAMPLE_ECC_PRIVATE_KEY_FILENAME_RECIPIENT
    //  - public_recipient: EXAMPLE_ECC_PUBLIC_KEY_FILENAME_RECIPIENT
    // This example uses BouncyCastle's KeyPairGenerator to generate the key pairs.
    // In practice, you should not generate this in your code, and should instead
    // retrieve this key from a secure key management system (e.g. HSM).
    // These examples only demonstrate using the P256 curve while the keyring accepts
    // P256, P384, or P521.
    // These keys are created here for example purposes only.
    KeyPairGenerator keyPairGenerator;
    try {
      if (Security.getProvider("BC") == null) {
        Security.addProvider(new BouncyCastleProvider());
      }
      keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
      keyPairGenerator.initialize(
        new ECGenParameterSpec("secp256r1"),
        new SecureRandom()
      );
    } catch (
      NoSuchAlgorithmException
      | InvalidAlgorithmParameterException
      | NoSuchProviderException exception
    ) {
      throw new IllegalStateException(
        "Bouncy Castle could not generate a secp256r1 key pair",
        exception
      );
    }

    KeyPair senderKeyPair = keyPairGenerator.generateKeyPair();
    KeyPair recipientKeyPair = keyPairGenerator.generateKeyPair();

    writePrivateKey(
      senderKeyPair.getPrivate(),
      EXAMPLE_ECC_PRIVATE_KEY_FILENAME_SENDER
    );
    writePrivateKey(
      recipientKeyPair.getPrivate(),
      EXAMPLE_ECC_PRIVATE_KEY_FILENAME_RECIPIENT
    );
    writePublicKey(
      (ECPublicKey) recipientKeyPair.getPublic(),
      EXAMPLE_ECC_PUBLIC_KEY_FILENAME_RECIPIENT
    );
  }

  private static void writePrivateKey(
    PrivateKey privateKey,
    String privateKeyFilename
  ) {
    StringWriter privateKeyStringWriter = new StringWriter();
    try (
      PemWriter privateKeyPemWriter = new PemWriter(privateKeyStringWriter)
    ) {
      privateKeyPemWriter.writeObject(
        new PemObject("PRIVATE KEY", privateKey.getEncoded())
      );
    } catch (IOException exception) {
      throw new UncheckedIOException(
        "IOException while writing private key PEM",
        exception
      );
    }

    // Write UTF8 encoded PEM file
    try {
      Files.writeString(
        Path.of(privateKeyFilename),
        privateKeyStringWriter.toString()
      );
    } catch (IOException exception) {
      throw new UncheckedIOException(
        "IOException while writing private key file",
        exception
      );
    }
  }

  private static void writePublicKey(
    ECPublicKey publicKey,
    String publicKeyFilename
  ) {
    StringWriter publicKeyStringWriter = new StringWriter();
    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
      publicKey.getEncoded()
    );

    try (PemWriter publicKeyPemWriter = new PemWriter(publicKeyStringWriter)) {
      publicKeyPemWriter.writeObject(
        new PemObject("PUBLIC KEY", publicKeySpec.getEncoded())
      );
    } catch (IOException exception) {
      throw new UncheckedIOException(
        "IOException while writing public key PEM",
        exception
      );
    }

    try {
      Files.writeString(
        Path.of(publicKeyFilename),
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
