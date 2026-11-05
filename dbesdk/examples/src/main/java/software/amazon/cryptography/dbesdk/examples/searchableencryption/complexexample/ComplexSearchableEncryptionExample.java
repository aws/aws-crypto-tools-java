package software.amazon.cryptography.dbesdk.examples.searchableencryption.complexexample;

import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

public class ComplexSearchableEncryptionExample {

  /*
   * This file is used in an example to demonstrate complex queries you can perform using beacons.
   * The example data used is for demonstrative purposes only, and might not meet the distribution
   * and correlation uniqueness recommendations for beacons. See our documentation for whether
   * beacons are right for your particular data set:
   * https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/searchable-encryption.html#are-beacons-right-for-me
   */
  public static void runExample(
    String tableName,
    String branchKeyId,
    String branchKeyWrappingKmsKeyArn,
    String keyStoreTableName
  ) {
    try (
      DynamoDbClient dynamoDbClient = ComplexExampleClientSetup.createDynamoDbClient(
        tableName,
        branchKeyId,
        branchKeyWrappingKmsKeyArn,
        keyStoreTableName
      )
    ) {
      PutRequests.putAllItemsToTable(tableName, dynamoDbClient);
      QueryRequests.runQueries(tableName, dynamoDbClient);
    }
  }

  public static void main(final String[] args) {
    if (args.length < 4) {
      throw new IllegalArgumentException(
        "To run this example, include tableName as args[0], " +
        "branchKeyId as args[1], branchKeyWrappingKmsKeyArn as args[2], and keyStoreTableName as args[3]"
      );
    }
    final String tableName = args[0];
    final String branchKeyId = args[1];
    final String branchKeyWrappingKmsKeyArn = args[2];
    final String keyStoreTableName = args[3];
    runExample(
      tableName,
      branchKeyId,
      branchKeyWrappingKmsKeyArn,
      keyStoreTableName
    );
  }
}
