package software.amazon.cryptography.dbesdk.examples.keyring;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
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
import software.amazon.cryptography.dbesdk.examples.ExampleUtils;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsEcdhKeyring;
import software.amazon.cryptography.materialproviders.keyrings.EcdhCurveSpec;
import software.amazon.cryptography.materialproviders.keyrings.KmsEcdhStaticConfigurations;

/*
 These examples set up DynamoDB Encryption for the AWS SDK client using the AWS KMS ECDH Keyring.
 This keyring, depending on its KeyAgreement scheme, takes in the sender's KMS ECC Key ARN, and the
 recipient's ECC Public Key to derive a shared secret. The keyring uses the shared secret to derive
 a data key to protect the data keys that encrypt and decrypt DynamoDB table items.

 Running these examples require access to the DynamoDB Table whose name is provided in CLI arguments.
 This table must be configured with the following primary key configuration:
   - Partition key is named "partition_key" with type (S)
   - Sort key is named "sort_key" with type (N)
*/
public class KmsEcdhKeyringExample {

  private static final String EXAMPLE_ECC_PUBLIC_KEY_SENDER_FILENAME =
    "KmsEccKeyringKeyringExamplePublicKeySender.pem";
  private static final String EXAMPLE_ECC_PUBLIC_KEY_RECIPIENT_FILENAME =
    "KmsEccKeyringKeyringExamplePublicKeyRecipient.pem";

  /*
    This example takes in the sender's KMS ECC key ARN, the sender's public key, the recipient's
    public key, and the algorithm definition where the ECC keys lie. The eccKeyArn parameter takes
    in the sender's KMS ECC key ARN, the eccPublicKeySenderFilename parameter takes in the sender's
    public key that corresponds to the eccKeyArn, the eccPublicKeyRecipientFilename parameter takes
    in the recipient's public key, and the Curve Specification where the keys lie.

    Both public keys MUST be UTF8 PEM-encoded X.509 public key, also known as
    SubjectPublicKeyInfo (SPKI).

    This example encrypts a test item using the provided ECC keys and puts the encrypted item to the
    provided DynamoDB table. Then, it gets the item from the table and decrypts it.

    Running this example requires access to the DynamoDB Table whose name is provided in CLI arguments.
    This table must be configured with the following primary key configuration:
      - Partition key is named "partition_key" with type (S)
      - Sort key is named "sort_key" with type (N)
    This example also requires access to a KMS ECC key. Our tests provide a KMS ECC Key ARN
    that anyone can use, but you can also provide your own KMS ECC key.
    To use your own KMS ECC key, you must have either:
      - Its public key downloaded in a UTF-8 encoded PEM file
      - kms:GetPublicKey permissions on that key.
    If you do not have the public key downloaded, running this example through its main method
    will download the public key for you by calling kms:GetPublicKey.
    You must also have kms:DeriveSharedSecret permissions on the KMS ECC key.
    This example also requires a recipient ECC Public Key that lies on the same curve as the
    sender public key. This examples uses another distinct KMS ECC Public Key, it does not have
    to be a KMS key; it can be a valid SubjectPublicKeyInfo (SPKI) Public Key.
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
    final byte[] recipientPublicKeyDer = loadPublicKeyBytes(
      eccPublicKeyRecipientFilename
    );
    final byte[] senderPublicKeyDer = loadPublicKeyBytes(
      eccPublicKeySenderFilename
    );

    // Create a KMS ECDH keyring.
    // This keyring uses the KmsPrivateKeyToStaticPublicKey configuration. This configuration calls for both of
    // the keys to be on the same curve (P256, P384, P521).
    // On encrypt, the keyring calls AWS KMS to derive the shared secret from the sender's KMS ECC Key ARN and the recipient's public key.
    // For this example, on decrypt, the keyring calls AWS KMS to derive the shared secret from the sender's KMS ECC Key ARN and the recipient's public key;
    // however, on decrypt, the recipient can construct a keyring such that the shared secret is calculated with
    // the recipient's private key and the sender's public key. In both scenarios the shared secret will be the same.
    // For more information on this configuration see:
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
    final Keyring kmsEcdhKeyring = AwsKmsEcdhKeyring
      .builder()
      .kmsClient(KmsClient.create())
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

  // This example takes in the recipient's KMS ECC key ARN via the eccRecipientKeyArn parameter.
  //
  // This example attempts to decrypt a test item using the provided eccRecipientKeyArn, it does so
  // by checking if the message header contains the recipient's public key.
  //
  // Running this example requires access to the DynamoDB Table whose name is provided in CLI arguments.
  // This table must be configured with the following primary key configuration:
  //   - Partition key is named "partition_key" with type (S)
  //   - Sort key is named "sort_key" with type (N)
  // This example also requires access to a KMS ECC key.
  // Our tests provide a KMS ECC Key ARN that anyone can use, but you can also provide your own
  // KMS ECC key.
  // To use your own KMS ECC key, you must have:
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
    // On decrypt, the keyring will check if its corresponding public key is stored in the message header. It
    // will AWS KMS to derive the shared from the recipient's KMS ECC Key ARN and the sender's public key;
    // For more information on this configuration see:
    // https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-kms-ecdh-keyring.html#kms-ecdh-discovery
    // The DynamoDB encryption client uses this to encrypt and decrypt items.
    // This keyring takes in:
    //  - kmsClient
    //  - recipientKmsIdentifier: Must be an ARN representing a KMS ECC key meant for KeyAgreement
    //  - curveSpec: The curve name where the public keys lie
    final Keyring kmsEcdhKeyring = AwsKmsEcdhKeyring
      .builder()
      .kmsClient(KmsClient.create())
      .curveSpec(EcdhCurveSpec.ECC_NIST_P256)
      .keyAgreementScheme(
        KmsEcdhStaticConfigurations.kmsPublicKeyDiscovery(eccRecipientKeyArn)
      )
      .build();

    getItemWithKeyring(kmsEcdhKeyring, tableName);
  }

  private static void getItemWithKeyring(
    Keyring kmsEcdhKeyring,
    String tableName
  ) {
    // Decide how each attribute of your items is protected. Give each attribute one of these
    // actions:
    // - encryptAndSign: the value is encrypted, so it cannot be read without the keys your keyring
    //   uses, and it is covered by the item's signature, so any change to it is detected when the
    //   item is read.
    // - signOnly: the value is stored as plain, readable text, but it is covered by the signature,
    //   so any change to it is detected.
    // - signAndIncludeInEncryptionContext: like signOnly, and the value is also handed to your
    //   keyring each time the item is encrypted or decrypted, for example so that a branch key ID
    //   supplier can pick a different key for each tenant. Using this action also requires
    //   signAndIncludePrimaryKeysInEncryptionContext(true) (see below).
    // - doNothing: the value is stored as plain text and is not covered by the signature, so a
    //   change to it is NOT detected.
    // Every attribute you write must either have an action or start with the prefix set below;
    // writing an item with any other attribute fails.
    //
    // Do not give the partition key or the sort key (together, the table's primary key) an action.
    // DynamoDB needs to read them to find the item, so they can never be encrypted, and the library
    // always signs them for you. By default they are signed like signOnly, and their values are
    // still handed to your keyring, in an encoded form. If you call
    // signAndIncludePrimaryKeysInEncryptionContext(true), they are signed like
    // signAndIncludeInEncryptionContext instead: their values are handed to your keyring as plain
    // text, and you can give other attributes the signAndIncludeInEncryptionContext action.

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
    final ItemEncryptionSchema schema = ItemEncryptionSchema
      .builder()
      .partitionKeyName("partition_key")
      .sortKeyName("sort_key")
      .encryptAndSign("sensitive_data")
      .doNothingPrefix(":")
      .build();

    // Create the DynamoDB Encryption configuration for the table we will be writing to.
    // Note: To use the KMS ECDH keyring, your table config must specify an algorithmSuite
    // that does not use asymmetric signing.
    final DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .logicalTableName(tableName)
      .schema(schema)
      .keyring(kmsEcdhKeyring)
      // Specify algorithmSuite without asymmetric signing here
      // As of v3.0.0, the only supported algorithmSuite without asymmetric signing is
      // ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384.
      .algorithmSuiteId(
        AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384
      )
      .build();

    // Create the DynamoDB Encryption Interceptor
    final DynamoDbEncryptionInterceptor encryptionInterceptor =
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
      final Map<String, AttributeValue> keyToGet = new HashMap<>();
      keyToGet.put(
        "partition_key",
        AttributeValue
          .builder()
          .s(ExampleUtils.uniquePartitionKey("awsKmsEcdhKeyringItem"))
          .build()
      );
      keyToGet.put("sort_key", AttributeValue.builder().n("0").build());

      final GetItemRequest getRequest = GetItemRequest
        .builder()
        .key(keyToGet)
        .tableName(tableName)
        .build();

      final GetItemResponse getResponse = dynamoDbClient.getItem(getRequest);

      // Demonstrate that GetItem succeeded and returned the decrypted item
      final Map<String, AttributeValue> returnedItem = getResponse.item();
      assert returnedItem.get("sensitive_data").s().equals("encrypt and sign me!");
    }
  }

  private static void putAndGetItemWithKeyring(
    Keyring awsKmsEcdhKeyring,
    String tableName
  ) {
    // Decide how each attribute of your items is protected. Give each attribute one of these
    // actions:
    // - encryptAndSign: the value is encrypted, so it cannot be read without the keys your keyring
    //   uses, and it is covered by the item's signature, so any change to it is detected when the
    //   item is read.
    // - signOnly: the value is stored as plain, readable text, but it is covered by the signature,
    //   so any change to it is detected.
    // - signAndIncludeInEncryptionContext: like signOnly, and the value is also handed to your
    //   keyring each time the item is encrypted or decrypted, for example so that a branch key ID
    //   supplier can pick a different key for each tenant. Using this action also requires
    //   signAndIncludePrimaryKeysInEncryptionContext(true) (see below).
    // - doNothing: the value is stored as plain text and is not covered by the signature, so a
    //   change to it is NOT detected.
    // Every attribute you write must either have an action or start with the prefix set below;
    // writing an item with any other attribute fails.
    //
    // Do not give the partition key or the sort key (together, the table's primary key) an action.
    // DynamoDB needs to read them to find the item, so they can never be encrypted, and the library
    // always signs them for you. By default they are signed like signOnly, and their values are
    // still handed to your keyring, in an encoded form. If you call
    // signAndIncludePrimaryKeysInEncryptionContext(true), they are signed like
    // signAndIncludeInEncryptionContext instead: their values are handed to your keyring as plain
    // text, and you can give other attributes the signAndIncludeInEncryptionContext action.

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
    final ItemEncryptionSchema schema = ItemEncryptionSchema
      .builder()
      .partitionKeyName("partition_key")
      .sortKeyName("sort_key")
      .encryptAndSign("sensitive_data")
      .doNothingPrefix(":")
      .build();

    // Create the DynamoDB Encryption configuration for the table we will be writing to.
    // Note: To use the KMS ECDH keyring, your table config must specify an algorithmSuite
    // that does not use asymmetric signing.
    final DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .logicalTableName(tableName)
      .schema(schema)
      .keyring(awsKmsEcdhKeyring)
      // Specify algorithmSuite without asymmetric signing here
      // As of v3.0.0, the only supported algorithmSuite without asymmetric signing is
      // ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384.
      .algorithmSuiteId(
        AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384
      )
      .build();

    // Create the DynamoDB Encryption Interceptor
    final DynamoDbEncryptionInterceptor encryptionInterceptor =
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
      final Map<String, AttributeValue> item = new HashMap<>();
      item.put(
        "partition_key",
        AttributeValue
          .builder()
          .s(ExampleUtils.uniquePartitionKey("awsKmsEcdhKeyringItem"))
          .build()
      );
      item.put("sort_key", AttributeValue.builder().n("0").build());
      item.put(
        "sensitive_data",
        AttributeValue.builder().s("encrypt and sign me!").build()
      );
      final PutItemRequest putRequest = PutItemRequest
        .builder()
        .tableName(tableName)
        .item(item)
        .build();

      dynamoDbClient.putItem(putRequest);

      // Get the item back from our table using the client.
      // The client will decrypt the item client-side using the ECDH keyring
      // and return the original item.
      final Map<String, AttributeValue> keyToGet = new HashMap<>();
      keyToGet.put(
        "partition_key",
        AttributeValue
          .builder()
          .s(ExampleUtils.uniquePartitionKey("awsKmsEcdhKeyringItem"))
          .build()
      );
      keyToGet.put("sort_key", AttributeValue.builder().n("0").build());

      final GetItemRequest getRequest = GetItemRequest
        .builder()
        .key(keyToGet)
        .tableName(tableName)
        .build();

      final GetItemResponse getResponse = dynamoDbClient.getItem(getRequest);

      // Demonstrate that GetItem succeeded and returned the decrypted item
      final Map<String, AttributeValue> returnedItem = getResponse.item();
      assert returnedItem.get("sensitive_data").s().equals("encrypt and sign me!");
    }
  }

  private static byte[] loadPublicKeyBytes(String eccPublicKeyFilename) {
    try {
      byte[] publicKeyFileBytes = Files.readAllBytes(
        Paths.get(eccPublicKeyFilename)
      );

      final PemObject pemObject;
      try (
        final PemReader pemReader = new PemReader(
          new InputStreamReader(new ByteArrayInputStream(publicKeyFileBytes))
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
      final SubjectPublicKeyInfo subjectPublicKeyInfo =
        SubjectPublicKeyInfo.getInstance(content);
      final X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(
        subjectPublicKeyInfo.getEncoded()
      );
      if (Security.getProvider("BC") == null) {
        Security.addProvider(new BouncyCastleProvider());
      }
      final KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
      final PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);
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

  public static void putAndGetItem(
    String tableName,
    String eccKeyArn
  ) {
    putAndGetItem(
      tableName,
      eccKeyArn,
      EXAMPLE_ECC_PUBLIC_KEY_SENDER_FILENAME,
      EXAMPLE_ECC_PUBLIC_KEY_RECIPIENT_FILENAME
    );
  }

  // To run the kmsEcdhKeyringGetItemPutItem as a standalone example you may provide the following
  // arguments in the following order.
  // - The DynamoDB Table Name you wish to read and write items to
  // - The sender's KMS ECC Key Arn, you MUST have kms:DeriveSharedSecret permission on the key.
  // - The sender's public key file name
  // - The recipient's public key file name
  // - The recipient's KMS ECC Key Arn, you must have kms:GetPublicKey permission on the key.
  public static void main(final String[] args) {
    if (args.length < 2) {
      throw new IllegalArgumentException(
        "To run this example, include the table name and eccKeyArn in args; optionally include" +
        " eccPublicKeySenderFilename, eccPublicKeyRecipientFilename, and eccRecipientKeyArn" +
        " arguments"
      );
    }
    final String tableName = args[0];
    final String eccKeyArn = args[1];
    final String eccPublicKeySenderFilename = args.length > 2
      ? args[2]
      : EXAMPLE_ECC_PUBLIC_KEY_SENDER_FILENAME;
    final String eccPublicKeyRecipientFilename = args.length > 3
      ? args[3]
      : EXAMPLE_ECC_PUBLIC_KEY_RECIPIENT_FILENAME;
    final String eccRecipientKeyArn = args.length > 4 ? args[4] : null;

    // You may provide your own ECC public keys at EXAMPLE_ECC_PUBLIC_KEY_SENDER_FILENAME and
    // EXAMPLE_ECC_PUBLIC_KEY_RECIPIENT_FILENAME.
    // The EXAMPLE_ECC_PUBLIC_KEY_SENDER_FILENAME must be the public key for the ECC key represented at eccKeyArn.
    //
    // If these files are not present, this will write a UTF-8 encoded PEM file for you.
    // In this example we use an ECC KMS Key as the recipient key. However; this is only for
    // example purposes. You can use an ECC Key that is not stored in KMS as the recipient public key.
    if (shouldGetNewPublicKeys()) {
      writePublicKeyPemForEccKey(
        eccKeyArn,
        EXAMPLE_ECC_PUBLIC_KEY_SENDER_FILENAME
      );
      writePublicKeyPemForEccKey(
        eccRecipientKeyArn,
        EXAMPLE_ECC_PUBLIC_KEY_RECIPIENT_FILENAME
      );
    }

    putAndGetItem(
      tableName,
      eccKeyArn,
      eccPublicKeySenderFilename,
      eccPublicKeyRecipientFilename
    );
  }

  static void writePublicKeyPemForEccKey(
    String eccKeyArn,
    String eccPublicKeyFilename
  ) {
    // Safety check: Validate file is not present
    final File publicKeyFile = new File(eccPublicKeyFilename);
    if (publicKeyFile.exists()) {
      throw new IllegalStateException(
        "writePublicKeyPemForEccKey will not overwrite existing PEM files"
      );
    }
    // This code will call KMS to get the public key for the KMS ECC key.
    // You must have kms:GetPublicKey permissions on the key for this to succeed.
    // The public key is written to eccPublicKeyFilename.
    final GetPublicKeyResponse response;
    try (KmsClient kmsClient = KmsClient.create()) {
      response =
        kmsClient.getPublicKey(
          GetPublicKeyRequest.builder().keyId(eccKeyArn).build()
        );
    }
    byte[] publicKeyByteArray = response.publicKey().asByteArray();

    final StringWriter publicKeyStringWriter = new StringWriter();
    final PemWriter publicKeyPemWriter = new PemWriter(publicKeyStringWriter);
    try {
      publicKeyPemWriter.writeObject(
        new PemObject("PUBLIC KEY", publicKeyByteArray)
      );
      publicKeyPemWriter.close();
    } catch (IOException exception) {
      throw new UncheckedIOException(
        "IOException while writing public key PEM",
        exception
      );
    }
    try {
      Files.write(
        Paths.get(eccPublicKeyFilename),
        publicKeyStringWriter.toString().getBytes(StandardCharsets.UTF_8)
      );
    } catch (IOException exception) {
      throw new UncheckedIOException(
        "IOException while writing public key file",
        exception
      );
    }
  }

  static boolean shouldGetNewPublicKeys() {
    // Check if public keys already exist
    final File senderPublicKeyFile = new File(
      EXAMPLE_ECC_PUBLIC_KEY_SENDER_FILENAME
    );
    final File recipientPublicKeyFile = new File(
      EXAMPLE_ECC_PUBLIC_KEY_RECIPIENT_FILENAME
    );

    return !senderPublicKeyFile.exists() && !recipientPublicKeyFile.exists();
  }
}
