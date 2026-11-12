package software.amazon.cryptography.dbesdk.examples.searchableencryption.complexexample;

import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;

/**
 * This class is used in an example to demonstrate complex queries you can perform using beacons.
 * The example data used is for demonstrative purposes only, and might not meet the distribution
 * and correlation uniqueness recommendations for beacons. See our documentation for whether
 * beacons are right for your particular data set:
 * https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/searchable-encryption.html#are-beacons-right-for-me
 */
public class ComplexSearchableEncryptionExample {

  public static void runExample(
    String tableName,
    String branchKeyId,
    String branchKeyWrappingKmsKeyArn,
    String keyStoreTableName
  ) {
    // The keystore's DynamoDB and AWS KMS clients are opened first, so try-with-resources closes them
    // last, after the encrypting client that uses the keystore. KmsClient.create() and
    // DynamoDbClient.create() use your environment's default region and credentials.
    try (
      DynamoDbClient keyStoreDynamoDbClient = DynamoDbClient.create();
      KmsClient keyStoreKmsClient = KmsClient.create();
      DynamoDbClient dynamoDbClient =
        ComplexExampleClientSetup.createDynamoDbClient(
          tableName,
          branchKeyId,
          branchKeyWrappingKmsKeyArn,
          keyStoreTableName,
          keyStoreDynamoDbClient,
          keyStoreKmsClient
        )
    ) {
      PutRequests.putAllItemsToTable(tableName, dynamoDbClient);
      QueryRequests.runQueries(tableName, dynamoDbClient);
    }
  }

  public static void main(String[] args) {
    if (args.length < 4) {
      throw new IllegalArgumentException(
        "To run this example, include tableName as args[0], " +
        "branchKeyId as args[1], branchKeyWrappingKmsKeyArn as args[2], and keyStoreTableName as args[3]"
      );
    }
    String tableName = args[0];
    String branchKeyId = args[1];
    String branchKeyWrappingKmsKeyArn = args[2];
    String keyStoreTableName = args[3];
    runExample(
      tableName,
      branchKeyId,
      branchKeyWrappingKmsKeyArn,
      keyStoreTableName
    );
  }
}
