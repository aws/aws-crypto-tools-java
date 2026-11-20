package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.keyring;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.ExampleUtils;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsEcdhKeyring;
import software.amazon.cryptography.materialproviders.keyrings.EcdhCurveSpec;
import software.amazon.cryptography.materialproviders.keyrings.KmsEcdhStaticConfigurations;

/**
 * These examples set up DynamoDB Encryption for the AWS SDK client using the AWS KMS ECDH Keyring.
 * This keyring, depending on its KeyAgreement scheme, takes in the sender's KMS ECC Key ARN, and the
 * recipient's ECC Public Key to derive a shared secret. The keyring uses the shared secret to derive
 * a data key to protect the data keys that encrypt and decrypt DynamoDB table items.
 *
 * <p>Running these examples requires access to the DynamoDB Table whose name is provided in CLI arguments.
 * This table must be configured with the following primary key configuration:
 *   - Partition key is named "partition_key" with type (S)
 *   - Sort key is named "sort_key" with type (N)
 */
public class KmsEcdhKeyringExample {

  private static final String EXAMPLE_ECC_PUBLIC_KEY_SENDER_FILENAME =
    "KmsEcdhKeyringExamplePublicKeySender.pem";
  private static final String EXAMPLE_ECC_PUBLIC_KEY_RECIPIENT_FILENAME =
    "KmsEcdhKeyringExamplePublicKeyRecipient.pem";

  /**
   * This example takes in the sender's KMS ECC key ARN and the files holding the sender's and the
   * recipient's public keys. The eccKeyArn parameter takes in the sender's KMS ECC key ARN, the
   * eccPublicKeySenderFilename parameter takes in the file holding the public key for eccKeyArn,
   * and the eccPublicKeyRecipientFilename parameter takes in the file holding the recipient's
   * public key. Both keys must be on the P-256 curve, which is the curve this example configures.
   *
   * <p>Each public key file must hold a UTF-8 PEM-encoded X.509 public key, also known as
   * SubjectPublicKeyInfo (SPKI).
   *
   * <p>This example encrypts a test item using the provided ECC keys and puts the encrypted item to the
   * provided DynamoDB table. Then, it gets the item from the table and decrypts it.
   *
   * <p>Running this example requires access to the DynamoDB Table whose name is provided in CLI arguments.
   * This table must be configured with the following primary key configuration:
   *   - Partition key is named "partition_key" with type (S)
   *   - Sort key is named "sort_key" with type (N)
   * This example also requires access to a KMS ECC key. For that key, you must have either:
   *   - Its public key downloaded in a UTF-8 encoded PEM file
   *   - kms:GetPublicKey permissions on that key.
   * If you do not have the public key downloaded, running this example through its main method
   * will download the public key for you by calling kms:GetPublicKey.
   * You must also have kms:DeriveSharedSecret permissions on the KMS ECC key.
   * This example also requires a recipient ECC Public Key that lies on the same curve as the
   * sender's public key. This example uses the public key of a second KMS ECC key. The recipient's
   * key does not have to be a KMS key; any valid SubjectPublicKeyInfo (SPKI) public key works.
   */
  public static void putAndGetItem(
    String tableName,
    String eccKeyArn,
    String eccPublicKeySenderFilename,
    String eccPublicKeyRecipientFilename
  ) {
    // Load UTF-8 encoded public key PEM files as DER encoded bytes.
    // You may provide your own PEM files to use here. If you provide this, it MUST
    // be a key on curve P256.
    // If not, the main method in this class will call
    // the KMS ECC key, retrieve its public key, and store it
    // in a PEM file for example use.
    byte[] recipientPublicKeyDer = loadPublicKeyBytes(
      eccPublicKeyRecipientFilename
    );
    byte[] senderPublicKeyDer = loadPublicKeyBytes(eccPublicKeySenderFilename);

    // Create a KMS ECDH keyring. This keyring uses the KmsPrivateKeyToStaticPublicKey
    // configuration. This configuration calls for both of the keys to be on the same curve (P256,
    // P384, P521). On encrypt, the keyring calls AWS KMS to derive the shared secret from the
    // sender's KMS ECC Key ARN and the recipient's public key. For this example, on decrypt, the
    // keyring calls AWS KMS to derive the shared secret from the sender's KMS ECC Key ARN and the
    // recipient's public key; however, on decrypt, the recipient can construct a keyring such that
    // the shared secret is calculated with the recipient's private key and the sender's public key.
    // In both scenarios the shared secret will be the same. For more information on this
    // configuration see:
    // https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-kms-ecdh-keyring.html#kms-ecdh-create
    // The DynamoDB encryption client uses this keyring to encrypt and decrypt items.
    // This keyring takes in:
    //  - kmsClient
    //  - kmsKeyId: Must be an ARN representing a KMS ECC key meant for KeyAgreement
    //  - curveSpec: The curve name where the public keys lie
    //  - senderPublicKey: A byte[] of the DER-encoded public
    //               key for the key passed into kmsKeyId
    //  - recipientPublicKey: A byte[] of the DER-encoded public
    //               key of the recipient
    // KmsClient.create() uses your environment's default region and credentials. The try block
    // closes the client when it ends, so everything that uses the keyring stays inside it.
    try (KmsClient kmsClient = KmsClient.create()) {
      Keyring kmsEcdhKeyring = AwsKmsEcdhKeyring
        .builder()
        .kmsClient(kmsClient)
        .curveSpec(EcdhCurveSpec.ECC_NIST_P256)
        .keyAgreementScheme(
          KmsEcdhStaticConfigurations.kmsPrivateKeyToStaticPublicKey(
            eccKeyArn,
            // Must be a DER-encoded X.509 public key
            senderPublicKeyDer,
            // Must be a DER-encoded X.509 public key
            recipientPublicKeyDer
          )
        )
        .build();

      putAndGetItemWithKeyring(kmsEcdhKeyring, tableName);
    }
  }

  // This example takes in the recipient's KMS ECC key ARN via the eccRecipientKeyArn parameter.
  //
  // This example attempts to decrypt a test item using the provided eccRecipientKeyArn. The keyring
  // decrypts only if the message header contains the recipient's public key.
  //
  // Running this example requires access to the DynamoDB Table whose name is provided in CLI arguments.
  // This table must be configured with the following primary key configuration:
  //   - Partition key is named "partition_key" with type (S)
  //   - Sort key is named "sort_key" with type (N)
  // This example also requires access to a KMS ECC key. For that key, you must have:
  //   - kms:GetPublicKey permissions on that key.
  // This example will call kms:GetPublicKey on keyring creation.
  // You must also have kms:DeriveSharedSecret permissions on the KMS ECC key.
  public static void getItemWithDiscoveryKeyring(
    String tableName,
    String eccRecipientKeyArn
  ) {
    // Create a KMS ECDH keyring.
    // This keyring uses the KmsPublicKeyDiscovery configuration.
    // On encrypt, the keyring will fail as it is not allowed to encrypt data under this configuration.
    // On decrypt, the keyring checks whether its own public key is stored in the message header. If
    // it is, the keyring calls AWS KMS to derive the shared secret from the recipient's KMS ECC Key
    // ARN and the sender's public key.
    // For more information on this configuration see:
    // https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-kms-ecdh-keyring.html#kms-ecdh-discovery
    // The DynamoDB encryption client uses this keyring to decrypt items.
    // This keyring takes in:
    //  - kmsClient
    //  - recipientKmsIdentifier: Must be an ARN representing a KMS ECC key meant for KeyAgreement
    //  - curveSpec: The curve name where the public keys lie
    // KmsClient.create() uses your environment's default region and credentials. The try block
    // closes the client when it ends, so everything that uses the keyring stays inside it.
    try (KmsClient kmsClient = KmsClient.create()) {
      Keyring kmsEcdhKeyring = AwsKmsEcdhKeyring
        .builder()
        .kmsClient(kmsClient)
        .curveSpec(EcdhCurveSpec.ECC_NIST_P256)
        .keyAgreementScheme(
          KmsEcdhStaticConfigurations.kmsPublicKeyDiscovery(eccRecipientKeyArn)
        )
        .build();

      getItemWithKeyring(kmsEcdhKeyring, tableName);
    }
  }

  private static void getItemWithKeyring(
    Keyring kmsEcdhKeyring,
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
    // Note: To use the KMS ECDH keyring, your table config must specify an algorithmSuite
    // that does not use asymmetric signing.
    DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .schema(schema)
      .keyring(kmsEcdhKeyring)
      // This keyring needs an algorithm suite without asymmetric signing.
      // ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384 is the only DB-ESDK
      // algorithm suite without it.
      .algorithmSuite(
        AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384
      )
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
      // Get the item back from our table using the client.
      // The client will decrypt the item client-side using the ECDH keyring
      // and return the original item.
      Map<String, AttributeValue> keyToGet = Map.of(
        "partition_key",
        AttributeValue.fromS(
          ExampleUtils.uniquePartitionKey("awsKmsEcdhKeyringItem")
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

  private static void putAndGetItemWithKeyring(
    Keyring awsKmsEcdhKeyring,
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
    // Note: To use the KMS ECDH keyring, your table config must specify an algorithmSuite
    // that does not use asymmetric signing.
    DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .schema(schema)
      .keyring(awsKmsEcdhKeyring)
      // This keyring needs an algorithm suite without asymmetric signing.
      // ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384 is the only DB-ESDK
      // algorithm suite without it.
      .algorithmSuite(
        AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384
      )
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
          ExampleUtils.uniquePartitionKey("awsKmsEcdhKeyringItem")
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

      // Get the item back from our table using the client.
      // The client will decrypt the item client-side using the ECDH keyring
      // and return the original item.
      Map<String, AttributeValue> keyToGet = Map.of(
        "partition_key",
        AttributeValue.fromS(
          ExampleUtils.uniquePartitionKey("awsKmsEcdhKeyringItem")
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

  private static byte[] loadPublicKeyBytes(String eccPublicKeyFilename) {
    try {
      PemObject pemObject;
      try (
        PemReader pemReader = new PemReader(
          Files.newBufferedReader(Path.of(eccPublicKeyFilename))
        )
      ) {
        pemObject = pemReader.readPemObject();
      }
      if (pemObject == null) {
        throw new IllegalArgumentException(
          eccPublicKeyFilename + " does not hold a PEM-encoded public key"
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
      return publicKey.getEncoded();
    } catch (IOException exception) {
      throw new UncheckedIOException(
        "IOException while reading public key from file",
        exception
      );
    } catch (
      NoSuchProviderException
      | NoSuchAlgorithmException
      | InvalidKeySpecException exception
    ) {
      throw new IllegalStateException(
        "Could not load the ECC public key",
        exception
      );
    }
  }

  // To run putAndGetItem as a standalone example through main, provide the following arguments in
  // this order.
  // - The DynamoDB Table Name you wish to read and write items to
  // - The sender's KMS ECC Key Arn, you MUST have kms:DeriveSharedSecret permission on the key.
  // - The sender's public key file name
  // - The recipient's public key file name
  // - The recipient's KMS ECC Key Arn, you must have kms:GetPublicKey permission on the key. This
  //   is needed only when the recipient's public key file does not exist yet.
  public static void main(String[] args) {
    if (args.length < 2) {
      throw new IllegalArgumentException(
        "To run this example, include the table name and eccKeyArn in args; optionally include" +
        " eccPublicKeySenderFilename, eccPublicKeyRecipientFilename, and eccRecipientKeyArn" +
        " arguments"
      );
    }
    String tableName = args[0];
    String eccKeyArn = args[1];
    String eccPublicKeySenderFilename = args.length > 2
      ? args[2]
      : EXAMPLE_ECC_PUBLIC_KEY_SENDER_FILENAME;
    String eccPublicKeyRecipientFilename = args.length > 3
      ? args[3]
      : EXAMPLE_ECC_PUBLIC_KEY_RECIPIENT_FILENAME;
    String eccRecipientKeyArn = args.length > 4 ? args[4] : null;

    // You may provide your own ECC public keys at eccPublicKeySenderFilename and
    // eccPublicKeyRecipientFilename. The sender's file must hold the public key for the ECC key
    // represented at eccKeyArn.
    //
    // If a file is not present, this writes it for you as a UTF-8 encoded PEM file, using the public
    // key AWS KMS returns for eccKeyArn (sender) or eccRecipientKeyArn (recipient).
    // In this example we use an ECC KMS Key as the recipient key. However, this is only for
    // example purposes. You can use an ECC Key that is not stored in KMS as the recipient public key.
    if (shouldGetNewPublicKey(eccPublicKeySenderFilename)) {
      writePublicKeyPemForEccKey(eccKeyArn, eccPublicKeySenderFilename);
    }
    if (shouldGetNewPublicKey(eccPublicKeyRecipientFilename)) {
      if (eccRecipientKeyArn == null) {
        throw new IllegalArgumentException(
          "No recipient public key file at " +
          eccPublicKeyRecipientFilename +
          "; include eccRecipientKeyArn in args so this example can write it"
        );
      }
      writePublicKeyPemForEccKey(
        eccRecipientKeyArn,
        eccPublicKeyRecipientFilename
      );
    }

    putAndGetItem(
      tableName,
      eccKeyArn,
      eccPublicKeySenderFilename,
      eccPublicKeyRecipientFilename
    );
  }

  private static void writePublicKeyPemForEccKey(
    String eccKeyArn,
    String eccPublicKeyFilename
  ) {
    // Safety check: Validate file is not present
    Path publicKeyFile = Path.of(eccPublicKeyFilename);
    if (Files.exists(publicKeyFile)) {
      throw new IllegalStateException(
        "writePublicKeyPemForEccKey will not overwrite existing PEM files"
      );
    }
    // This code will call KMS to get the public key for the KMS ECC key.
    // You must have kms:GetPublicKey permissions on the key for this to succeed.
    // The public key is written to eccPublicKeyFilename.
    GetPublicKeyResponse response;
    try (KmsClient kmsClient = KmsClient.create()) {
      response =
        kmsClient.getPublicKey(
          GetPublicKeyRequest.builder().keyId(eccKeyArn).build()
        );
    }
    byte[] publicKeyByteArray = response.publicKey().asByteArray();

    StringWriter publicKeyStringWriter = new StringWriter();
    try (PemWriter publicKeyPemWriter = new PemWriter(publicKeyStringWriter)) {
      publicKeyPemWriter.writeObject(
        new PemObject("PUBLIC KEY", publicKeyByteArray)
      );
    } catch (IOException exception) {
      throw new UncheckedIOException(
        "IOException while writing public key PEM",
        exception
      );
    }
    try {
      Files.writeString(
        Path.of(eccPublicKeyFilename),
        publicKeyStringWriter.toString()
      );
    } catch (IOException exception) {
      throw new UncheckedIOException(
        "IOException while writing public key file",
        exception
      );
    }
  }

  private static boolean shouldGetNewPublicKey(String eccPublicKeyFilename) {
    // If the file is not present, get the public key from KMS
    return !Files.exists(Path.of(eccPublicKeyFilename));
  }
}
