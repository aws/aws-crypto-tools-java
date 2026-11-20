package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.keystore;

import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;

/**
 * The Hierarchical Keyring Example and Searchable Encryption Examples rely on the existence of a
 * DynamoDB-backed key store with pre-existing branch key material or beacon key material.
 *
 * <p>See the "Create KeyStore Table Example" for how to first set up the DynamoDB Table that will back this
 * KeyStore.
 *
 * <p>This example demonstrates configuring a KeyStore and then using a helper method to create a branch
 * key and beacon key that share the same Id, then return that Id. We will always create a new beacon
 * key alongside a new branch key, even if you are not using searchable encryption.
 *
 * <p>This key creation should occur within your control plane.
 */
public class CreateKeyStoreKeyExample {

  public static String createBranchKey(
    String keyStoreTableName,
    String logicalKeyStoreName,
    String kmsKeyArn
  ) {
    // 1. Configure your KeyStore resource. This SHOULD be the same configuration that was used to
    // create the DynamoDB table in the "Create KeyStore Table Example".
    // The DynamoDB and AWS KMS clients the keystore uses. Both are optional: without them, the
    // keystore creates its own in the region of the KMS key ARN. KmsClient.create() and
    // DynamoDbClient.create() use your environment's default region and credentials instead.
    // The try block closes them when it ends, so everything that uses the keystore stays inside it.
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

      // 2. Create a new branch key and beacon key in our KeyStore. Both the branch key and the beacon
      // key will share an Id. This creation is eventually consistent.
      return keyStore.createKey().branchKeyIdentifier();
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
    createBranchKey(keyStoreTableName, logicalKeyStoreName, kmsKeyArn);
  }
}
