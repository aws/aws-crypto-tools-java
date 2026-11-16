package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.keystore;

import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;

/**
 * The Hierarchical Keyring Example and Searchable Encryption Examples rely on the existence of a
 * DynamoDB-backed key store with pre-existing branch key material or beacon key material.
 *
 * <p>This example demonstrates configuring a KeyStore and then using a helper method to create the DynamoDB
 * table that will be used to persist branch keys and beacons keys for this KeyStore.
 *
 * <p>This table creation should occur within your control plane. This only needs to occur once. While
 * not demonstrated in this example, you should additionally use the `VersionKey` API on the KeyStore
 * to periodically rotate your branch key material.
 */
public class CreateKeyStoreTableExample {

  public static void createKeyStoreTable(
    String keyStoreTableName,
    String logicalKeyStoreName,
    String kmsKeyArn
  ) {
    // 1. Configure your KeyStore resource. `ddbTableName` is the name you want for the DynamoDB table
    // that will back your keystore. `kmsKeyArn` is the KMS Key that will protect your branch keys
    // and beacon keys when they are stored in your DynamoDB table.
    // The DynamoDB and AWS KMS clients the keystore uses. Both are optional: without them, the
    // keystore creates its own in the region of the KMS key ARN. KmsClient.create() and
    // DynamoDbClient.create() use your environment's default region and credentials instead.
    // Pass clients built for your needs when you need different credentials, a specific region
    // (for example, a keystore table in a different region from the KMS key), a custom endpoint
    // or retry settings, or to reuse clients your application already has. The try block closes
    // them when it ends, so everything that uses the keystore stays inside it.
    try (
      DynamoDbClient keyStoreDynamoDbClient = DynamoDbClient.create();
      KmsClient keyStoreKmsClient = KmsClient.create()
    ) {
      BranchKeyStore keyStore = BranchKeyStore
        .builder()
        .ddbTableName(keyStoreTableName)
        .logicalKeyStoreName(logicalKeyStoreName)
        .kmsConfiguration(KmsConfiguration.kmsKeyArn(kmsKeyArn))
        .ddbClient(keyStoreDynamoDbClient)
        .kmsClient(keyStoreKmsClient)
        .build();

      // 2. Create the DynamoDB table that will store the branch keys and beacon keys. This checks if
      // the correct table already exists at `ddbTableName` by using the DescribeTable API. If no
      // table exists, it will create one. If a table exists, it will verify the table's configuration
      // and will error if the configuration is incorrect.
      keyStore.createKeyStore();
      // It may take a couple minutes for the table to become ACTIVE, at which point it is ready to
      // store branch and beacon keys. See the Create KeyStore Key Example for how to populate this
      // table.
    }
  }

  public static void main(String[] args) {
    if (args.length < 3) {
      throw new IllegalArgumentException(
        "To run this example, include the keyStoreTableName, logicalKeyStoreName, and kmsKeyArn in args"
      );
    }
    String keyStoreTableName = args[0];
    String logicalKeyStoreName = args[1];
    String kmsKeyArn = args[2];
    createKeyStoreTable(keyStoreTableName, logicalKeyStoreName, kmsKeyArn);
  }
}
