package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling;

import java.time.Duration;
import java.util.Map;
import software.amazon.awssdk.arns.Arn;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.ResourceNotFoundException;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.exceptions.BranchKeyResource;
import software.amazon.cryptography.materialproviders.exceptions.KmsKeyResource;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkMultiKeyring;

/**
 * Shows what the DB-ESDK throws when a keyring names a branch key or a KMS key that does not exist.
 *
 * <p>Both cases throw {@link ResourceNotFoundException}. Its {@code resource()} names the missing
 * key: a {@link BranchKeyResource} for a branch key, a {@link KmsKeyResource} for a KMS key.
 * Create the key, or correct the key ID or ARN in the keyring's configuration; a retry gets the
 * same result.
 *
 * <p>Running this example needs AWS credentials, a key store, and a DynamoDB table with partition
 * key "partition_key" (S) and sort key "sort_key" (N).
 */
public class KeyNotFoundExample {

  private static final String PARTITION_KEY = "partition_key";
  private static final String SORT_KEY = "sort_key";
  // This example relies on the key store having no branch key with this ID.
  private static final String MISSING_BRANCH_KEY_ID =
    "branch-key-that-does-not-exist";
  // A KMS key ID has the form of a UUID. This one is well formed, so AWS KMS looks it up and
  // answers that it does not exist, instead of rejecting the request as malformed. This example
  // relies on the account having no KMS key with this ID.
  private static final String MISSING_KMS_KEY_ID =
    "00000000-0000-0000-0000-000000000000";

  public static void keyNotFound(
    String tableName,
    String keyStoreTableName,
    String logicalKeyStoreName,
    String kmsKeyArn
  ) {
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

      // The key store has no branch key with this ID.
      Keyring missingBranchKeyKeyring = AwsKmsHierarchicalKeyring
        .builder()
        .branchKeyId(MISSING_BRANCH_KEY_ID)
        .keyStore(keyStore)
        .ttl(Duration.ofMinutes(10))
        .build();
      // A KMS key in the same account and Region as kmsKeyArn, which does not exist.
      String missingKmsKeyArn = Arn
        .fromString(kmsKeyArn)
        .toBuilder()
        .resource("key/" + MISSING_KMS_KEY_ID)
        .build()
        .toString();
      Keyring missingKmsKeyKeyring = AwsKmsMrkMultiKeyring
        .builder()
        .generator(missingKmsKeyArn)
        .build();

      ItemEncryptionSchema schema = ItemEncryptionSchema
        .builder()
        .partitionKeyName(PARTITION_KEY)
        .sortKeyName(SORT_KEY)
        .encryptAndSign("attribute1")
        .build();
      DynamoDbTableEncryptionConfig missingBranchKeyTableConfig =
        DynamoDbTableEncryptionConfig
          .builder()
          .tableName(tableName)
          .schema(schema)
          .keyring(missingBranchKeyKeyring)
          .build();
      DynamoDbEncryptionInterceptor missingBranchKeyInterceptor =
        DynamoDbEncryptionInterceptor
          .builder()
          .tableConfigs(missingBranchKeyTableConfig)
          .build();
      DynamoDbTableEncryptionConfig missingKmsKeyTableConfig =
        DynamoDbTableEncryptionConfig
          .builder()
          .tableName(tableName)
          .schema(schema)
          .keyring(missingKmsKeyKeyring)
          .build();
      DynamoDbEncryptionInterceptor missingKmsKeyInterceptor =
        DynamoDbEncryptionInterceptor
          .builder()
          .tableConfigs(missingKmsKeyTableConfig)
          .build();

      PutItemRequest write = PutItemRequest
        .builder()
        .tableName(tableName)
        .item(
          Map.of(
            PARTITION_KEY,
            AttributeValue.fromS("KeyNotFoundExample"),
            SORT_KEY,
            AttributeValue.fromN("0"),
            "attribute1",
            AttributeValue.fromS("encrypt and sign me!")
          )
        )
        .build();

      try (
        DynamoDbClient missingBranchKeyClient = DynamoDbClient
          .builder()
          .overrideConfiguration(overrides ->
            overrides.addExecutionInterceptor(missingBranchKeyInterceptor)
          )
          .build();
        DynamoDbClient missingKmsKeyClient = DynamoDbClient
          .builder()
          .overrideConfiguration(overrides ->
            overrides.addExecutionInterceptor(missingKmsKeyInterceptor)
          )
          .build()
      ) {
        branchKeyThatDoesNotExist(missingBranchKeyClient, write);
        kmsKeyThatDoesNotExist(missingKmsKeyClient, write);
      }
    }
  }

  private static void branchKeyThatDoesNotExist(
    DynamoDbClient dynamoDbClient,
    PutItemRequest write
  ) {
    try {
      dynamoDbClient.putItem(write);
    } catch (ResourceNotFoundException exception) {
      if (exception.resource() instanceof BranchKeyResource branchKey) {
        System.err.println(
          "The key store has no branch key " +
          branchKey.id() +
          ". Create it, or correct the branch key ID in the keyring."
        );
        return;
      }
      throw exception;
    }
    throw new IllegalStateException(
      "Writing with a branch key that does not exist succeeded"
    );
  }

  private static void kmsKeyThatDoesNotExist(
    DynamoDbClient dynamoDbClient,
    PutItemRequest write
  ) {
    try {
      dynamoDbClient.putItem(write);
    } catch (ResourceNotFoundException exception) {
      if (exception.resource() instanceof KmsKeyResource kmsKey) {
        System.err.println(
          "The KMS key " +
          kmsKey.arn() +
          " does not exist. Create it, or correct the KMS key ARN in the keyring."
        );
        return;
      }
      throw exception;
    }
    throw new IllegalStateException(
      "Writing with a KMS key that does not exist succeeded"
    );
  }

  public static void main(String[] args) {
    if (args.length < 4) {
      throw new IllegalArgumentException(
        "To run this example, include the tableName, keyStoreTableName, " +
        "logicalKeyStoreName and kmsKeyArn in args"
      );
    }
    keyNotFound(args[0], args[1], args[2], args[3]);
  }
}
