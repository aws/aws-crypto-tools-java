package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.keyring;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.ExampleUtils;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsRsaKeyring;

/**
 * This example sets up DynamoDB Encryption for the AWS SDK client using the KMS RSA Keyring. This
 * keyring uses a KMS RSA key pair to encrypt and decrypt records. The client uses the downloaded
 * public key to encrypt items it adds to the table. The keyring uses the private key to decrypt
 * existing table items it retrieves, by calling KMS' decrypt API.
 *
 * <p>Running this example requires access to the DynamoDB Table whose name is provided in CLI arguments. This
 * table must be configured with the following primary key configuration:
 *   - Partition key is named "partition_key" with type (S)
 *   - Sort key is named "sort_key" with type (N)
 * This example also requires access to a KMS RSA key. For that key, you must have either:
 *  - Its public key downloaded in a UTF-8 encoded PEM file
 *  - kms:GetPublicKey permissions on that key
 * If you do not have the public key downloaded, running this example through its main method
 * will download the public key for you by calling kms:GetPublicKey.
 * You must also have kms:Decrypt permissions on the KMS RSA key.
 */
public class KmsRsaKeyringExample {

  private static final String DEFAULT_EXAMPLE_RSA_PUBLIC_KEY_FILENAME =
    "KmsRsaKeyringExamplePublicKey.pem";

  public static void putAndGetItem(
    String tableName,
    String rsaKeyArn,
    String rsaPublicKeyFilename
  ) {
    // 1. Load UTF-8 encoded public key PEM file.
    //    You may have an RSA public key file already defined.
    //    If not, the main method in this class will call
    //    the KMS RSA key, retrieve its public key, and store it
    //    in a PEM file for example use.
    byte[] publicKeyUtf8EncodedBytes;
    try {
      publicKeyUtf8EncodedBytes =
        Files.readAllBytes(Path.of(rsaPublicKeyFilename));
    } catch (IOException exception) {
      throw new UncheckedIOException(
        "IOException while reading public key from file",
        exception
      );
    }

    // 2. Create a KMS RSA keyring. This keyring takes in:
    // - kmsClient
    // - kmsKeyId: Must be an ARN representing a KMS RSA key
    // - publicKey: A byte[] of a UTF-8 encoded PEM file representing the public key for the key
    // passed into kmsKeyId
    // - encryptionAlgorithm: Must be either RSAES_OAEP_SHA_256 or RSAES_OAEP_SHA_1
    // KmsClient.create() uses your environment's default region and credentials. The try block
    // closes the client when it ends, so everything that uses the keyring stays inside it.
    try (KmsClient kmsClient = KmsClient.create()) {
      Keyring kmsRsaKeyring = AwsKmsRsaKeyring
        .builder()
        .kmsClient(kmsClient)
        .kmsKeyId(rsaKeyArn)
        .publicKey(publicKeyUtf8EncodedBytes)
        .encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)
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
      //    Note: To use the KMS RSA keyring, your table config must specify an algorithmSuite
      //    that does not use asymmetric signing.
      DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
        .builder()
        .tableName(tableName)
        .schema(schema)
        .keyring(kmsRsaKeyring)
        // This keyring needs an algorithm suite without asymmetric signing.
        // ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384 is the only DB-ESDK
        // algorithm suite without it.
        .algorithmSuite(
          AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384
        )
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
            ExampleUtils.uniquePartitionKey("awsKmsRsaKeyringItem")
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

        // 9. Get the item back from our table using the client.
        //    The client will decrypt the item client-side using the RSA keyring
        //    and return the original item.
        Map<String, AttributeValue> keyToGet = Map.of(
          "partition_key",
          AttributeValue.fromS(
            ExampleUtils.uniquePartitionKey("awsKmsRsaKeyringItem")
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
  }

  public static void main(String[] args) {
    if (args.length < 2) {
      throw new IllegalArgumentException(
        "To run this example, include the table name and rsaKeyArn in args; optionally include" +
        " rsaPublicKeyFilename"
      );
    }
    String tableName = args[0];
    String rsaKeyArn = args[1];
    String rsaPublicKeyFilename = args.length > 2
      ? args[2]
      : DEFAULT_EXAMPLE_RSA_PUBLIC_KEY_FILENAME;

    // You may provide your own RSA public key at DEFAULT_EXAMPLE_RSA_PUBLIC_KEY_FILENAME.
    // This must be the public key for the RSA key represented at rsaKeyArn.
    // If this file is not present, this will write a UTF-8 encoded PEM file for you.
    if (shouldGetNewPublicKey(rsaPublicKeyFilename)) {
      writePublicKeyPemForRsaKey(rsaKeyArn, rsaPublicKeyFilename);
    }

    putAndGetItem(tableName, rsaKeyArn, rsaPublicKeyFilename);
  }

  private static boolean shouldGetNewPublicKey(String rsaPublicKeyFilename) {
    // If the file is not present, download the public key from KMS
    return !Files.exists(Path.of(rsaPublicKeyFilename));
  }

  private static void writePublicKeyPemForRsaKey(
    String rsaKeyArn,
    String rsaPublicKeyFilename
  ) {
    // Safety check: Validate file is not present
    Path publicKeyFile = Path.of(rsaPublicKeyFilename);
    if (Files.exists(publicKeyFile)) {
      throw new IllegalStateException(
        "writePublicKeyPemForRsaKey will not overwrite existing PEM files"
      );
    }

    // This code will call KMS to get the public key for the KMS RSA key.
    // You must have kms:GetPublicKey permissions on the key for this to succeed.
    // The public key will be written to the file rsaPublicKeyFilename.
    GetPublicKeyResponse response;
    try (KmsClient kmsClient = KmsClient.create()) {
      response =
        kmsClient.getPublicKey(
          GetPublicKeyRequest.builder().keyId(rsaKeyArn).build()
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
        Path.of(rsaPublicKeyFilename),
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
