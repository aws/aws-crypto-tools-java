package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling.searchableencryption;

import java.time.Duration;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconKeySource;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.StandardBeacon;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.ValidationException;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;

/**
 * Shows the searches on encrypted attributes that the DB-ESDK cannot rewrite, and the exception it
 * throws for each.
 *
 * <p>A beacon lets you search an encrypted attribute: the DB-ESDK writes a short hash of the value
 * next to it, and rewrites your query to compare hashes.
 *
 * <p>The DB-ESDK can rewrite only some searches, so it rejects the rest before anything is sent,
 * with {@link ValidationException}: a search on an encrypted attribute that has no beacon, an
 * operation that a beacon cannot answer (for example {@code <} on a standard beacon), and a name or
 * value missing from the expression maps. A Scan that sets a value for ":aws_dbe_partition", the
 * beacon partition number, is rejected the same way. Change the request; a retry gets the same
 * result.
 *
 * <p>Running this example needs AWS credentials, a key store, and a branch key in it to use as the
 * beacon key. Every request below is rejected before it is sent, so the table does not have to
 * exist.
 */
public class BeaconSearchErrorsExample {

  private static final String PARTITION_KEY = "work_id";
  private static final String SORT_KEY = "inspection_date";
  private static final String INSPECTOR_ID_LAST4 = "inspector_id_last4";
  private static final String NOTES = "notes";

  public static void sendUnsupportedBeaconSearches(
    String tableName,
    String branchKeyId,
    String keyStoreTableName,
    String branchKeyWrappingKmsKeyArn
  ) {
    try (
      DynamoDbClient keyStoreDynamoDbClient = DynamoDbClient.create();
      KmsClient keyStoreKmsClient = KmsClient.create()
    ) {
      BranchKeyStore keyStore = BranchKeyStore
        .builder()
        .ddbTableName(keyStoreTableName)
        .logicalKeyStoreName(keyStoreTableName)
        .kmsConfiguration(
          KmsConfiguration.kmsKeyArn(branchKeyWrappingKmsKeyArn)
        )
        .ddbClient(keyStoreDynamoDbClient)
        .kmsClient(keyStoreKmsClient)
        .build();
      Keyring hierarchicalKeyring = AwsKmsHierarchicalKeyring
        .builder()
        .branchKeyId(branchKeyId)
        .keyStore(keyStore)
        .ttl(Duration.ofMinutes(10))
        .build();

      // Both attributes are encrypted. inspector_id_last4 has a standard beacon; notes has none.
      ItemEncryptionSchema schema = ItemEncryptionSchema
        .builder()
        .partitionKeyName(PARTITION_KEY)
        .sortKeyName(SORT_KEY)
        .encryptAndSign(INSPECTOR_ID_LAST4, NOTES)
        .build();
      StandardBeacon last4Beacon = StandardBeacon
        .builder()
        .name(INSPECTOR_ID_LAST4)
        .bitLength(10)
        .build();
      BeaconKeySource beaconKeySource = BeaconKeySource
        .singleBeaconKey(branchKeyId)
        .cacheTtl(Duration.ofMinutes(10))
        .build();
      BeaconConfig beaconConfig = BeaconConfig
        .builder()
        .standardBeacons(last4Beacon)
        .keyStore(keyStore)
        .keySource(beaconKeySource)
        .build();
      DynamoDbTableEncryptionConfig tableConfig = DynamoDbTableEncryptionConfig
        .builder()
        .tableName(tableName)
        .schema(schema)
        .keyring(hierarchicalKeyring)
        .beaconConfig(beaconConfig)
        .build();
      DynamoDbEncryptionInterceptor encryptionInterceptor =
        DynamoDbEncryptionInterceptor
          .builder()
          .tableConfigs(tableConfig)
          .build();

      try (
        DynamoDbClient dynamoDbClient = DynamoDbClient
          .builder()
          .overrideConfiguration(overrides ->
            overrides.addExecutionInterceptor(encryptionInterceptor)
          )
          .build()
      ) {
        scanEncryptedAttributeWithoutBeacon(dynamoDbClient, tableName);
        scanStandardBeaconWithLessThan(dynamoDbClient, tableName);
        scanWithValueMissingFromExpressionMap(dynamoDbClient, tableName);
      }
    }
  }

  // notes is encrypted and has no beacon, so DynamoDB has nothing to compare it with.
  private static void scanEncryptedAttributeWithoutBeacon(
    DynamoDbClient dynamoDbClient,
    String tableName
  ) {
    ScanRequest request = ScanRequest
      .builder()
      .tableName(tableName)
      .filterExpression(NOTES + " = :notes")
      .expressionAttributeValues(
        Map.of(":notes", AttributeValue.fromS("passed"))
      )
      .build();
    try {
      dynamoDbClient.scan(request);
    } catch (ValidationException exception) {
      System.err.println(
        "Add a beacon for each encrypted attribute you want to search: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "A search on an encrypted attribute without a beacon was sent"
    );
  }

  // A standard beacon is a hash, so it can tell whether two values are equal, but not which one is
  // smaller.
  private static void scanStandardBeaconWithLessThan(
    DynamoDbClient dynamoDbClient,
    String tableName
  ) {
    ScanRequest request = ScanRequest
      .builder()
      .tableName(tableName)
      .filterExpression(INSPECTOR_ID_LAST4 + " < :last4")
      .expressionAttributeValues(Map.of(":last4", AttributeValue.fromS("5000")))
      .build();
    try {
      dynamoDbClient.scan(request);
    } catch (ValidationException exception) {
      System.err.println(
        "Search a standard beacon only for equality: " + exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "A less-than search on a standard beacon was sent"
    );
  }

  // The DB-ESDK reads each value from ExpressionAttributeValues to compute its beacon. Here :last4
  // is missing.
  private static void scanWithValueMissingFromExpressionMap(
    DynamoDbClient dynamoDbClient,
    String tableName
  ) {
    ScanRequest request = ScanRequest
      .builder()
      .tableName(tableName)
      .filterExpression(INSPECTOR_ID_LAST4 + " = :last4")
      .build();
    try {
      dynamoDbClient.scan(request);
    } catch (ValidationException exception) {
      System.err.println(
        "Supply every value that the expression uses: " + exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "A search with a value missing from ExpressionAttributeValues was sent"
    );
  }

  public static void main(String[] args) {
    if (args.length < 4) {
      throw new IllegalArgumentException(
        "To run this example, include the tableName, branchKeyId, keyStoreTableName and " +
        "branchKeyWrappingKmsKeyArn in args"
      );
    }
    sendUnsupportedBeaconSearches(args[0], args[1], args[2], args[3]);
  }
}
