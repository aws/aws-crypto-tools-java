package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.AccessDeniedException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.CustomComponentException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.ResourceNotFoundException;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.exceptions.BranchKeyResource;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;
import software.amazon.cryptography.materialproviders.keystore.GetActiveBranchKeyRequest;
import software.amazon.cryptography.materialproviders.keystore.GetActiveBranchKeyResponse;
import software.amazon.cryptography.materialproviders.keystore.GetBeaconKeyRequest;
import software.amazon.cryptography.materialproviders.keystore.GetBeaconKeyResponse;
import software.amazon.cryptography.materialproviders.keystore.GetBranchKeyVersionRequest;
import software.amazon.cryptography.materialproviders.keystore.GetBranchKeyVersionResponse;
import software.amazon.cryptography.materialproviders.keystore.GetKeyStoreInfoRequest;
import software.amazon.cryptography.materialproviders.keystore.GetKeyStoreInfoResponse;
import software.amazon.cryptography.materialproviders.keystore.KeyStore;

/**
 * Shows what the DB-ESDK throws when a key store that you implemented fails.
 *
 * <p>When a component that you implemented throws, its exception arrives as the cause of a {@link
 * CustomComponentException}, whose {@code resource()} names the component.
 *
 * <p>When your component throws an AWS SDK exception or a materialproviders exception, the DB-ESDK
 * reports it with that exception's kind instead, so a throttled call stays retryable.
 *
 * <p>For a key store, {@code resource()} is the branch key that it was reading.
 *
 * <p>Running this example needs AWS credentials, a key store with a branch key in it, and a
 * DynamoDB table with partition key "partition_key" (S) and sort key "sort_key" (N).
 */
public class CustomKeyStoreErrorsExample {

  private static final String PARTITION_KEY = "partition_key";
  private static final String SORT_KEY = "sort_key";
  private static final String ENCRYPTED_ATTRIBUTE = "attribute1";
  // This example relies on no table with this name existing in the account and Region.
  private static final String MISSING_AUDIT_TABLE =
    "audit-table-that-does-not-exist";

  public static void customKeyStoreErrors(
    String tableName,
    String branchKeyId,
    String keyStoreTableName,
    String logicalKeyStoreName,
    String kmsKeyArn
  ) {
    try (
      DynamoDbClient keyStoreDynamoDbClient = DynamoDbClient.create();
      KmsClient keyStoreKmsClient = KmsClient.create();
      DynamoDbClient auditDynamoDbClient = DynamoDbClient.create()
    ) {
      BranchKeyStore keyStore = BranchKeyStore
        .builder()
        .ddbTableName(keyStoreTableName)
        .logicalKeyStoreName(logicalKeyStoreName)
        .kmsConfiguration(KmsConfiguration.kmsKeyArn(kmsKeyArn))
        .ddbClient(keyStoreDynamoDbClient)
        .kmsClient(keyStoreKmsClient)
        .build();
      // The audit table does not exist, so each audit write fails.
      AuditingKeyStore auditingKeyStore = new AuditingKeyStore(
        keyStore,
        auditDynamoDbClient,
        MISSING_AUDIT_TABLE
      );
      Keyring hierarchicalKeyring = AwsKmsHierarchicalKeyring
        .builder()
        .branchKeyId(branchKeyId)
        .keyStore(auditingKeyStore)
        .ttl(Duration.ofMinutes(10))
        .build();

      ItemEncryptionSchema schema = ItemEncryptionSchema
        .builder()
        .partitionKeyName(PARTITION_KEY)
        .sortKeyName(SORT_KEY)
        .encryptAndSign(ENCRYPTED_ATTRIBUTE)
        .build();
      DynamoDbTableEncryptionConfig tableConfig = DynamoDbTableEncryptionConfig
        .builder()
        .tableName(tableName)
        .schema(schema)
        .keyring(hierarchicalKeyring)
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
        awsExceptionFromYourOwnKeyStore(dynamoDbClient, tableName);
      }
    }
  }

  /**
   * A key store that gets branch keys from a BranchKeyStore and records each one that it hands out
   * in this application's audit table.
   */
  static final class AuditingKeyStore implements KeyStore {

    private final KeyStore delegate;
    private final DynamoDbClient auditDynamoDbClient;
    private final String auditTableName;

    AuditingKeyStore(
      KeyStore delegate,
      DynamoDbClient auditDynamoDbClient,
      String auditTableName
    ) {
      this.delegate = delegate;
      this.auditDynamoDbClient = auditDynamoDbClient;
      this.auditTableName = auditTableName;
    }

    @Override
    public GetActiveBranchKeyResponse getActiveBranchKey(
      GetActiveBranchKeyRequest request
    ) {
      audit(request.branchKeyId());
      return delegate.getActiveBranchKey(request);
    }

    @Override
    public GetBranchKeyVersionResponse getBranchKeyVersion(
      GetBranchKeyVersionRequest request
    ) {
      audit(request.branchKeyId());
      return delegate.getBranchKeyVersion(request);
    }

    @Override
    public GetBeaconKeyResponse getBeaconKey(GetBeaconKeyRequest request) {
      return delegate.getBeaconKey(request);
    }

    @Override
    public GetKeyStoreInfoResponse getKeyStoreInfo(
      GetKeyStoreInfoRequest request
    ) {
      return delegate.getKeyStoreInfo(request);
    }

    private void audit(String branchKeyId) {
      PutItemRequest auditRecord = PutItemRequest
        .builder()
        .tableName(auditTableName)
        .item(
          Map.of(
            "branch_key_id",
            AttributeValue.fromS(branchKeyId),
            "read_at",
            AttributeValue.fromS(Instant.now().toString())
          )
        )
        .build();
      auditDynamoDbClient.putItem(auditRecord);
    }
  }

  // The DB-ESDK reports an AWS SDK exception from your component with the same kind that it gives
  // that AWS error in its own calls.
  // DynamoDB answers ResourceNotFoundException for the missing audit table. If the caller's IAM
  // policy allows only certain tables, DynamoDB answers AccessDeniedException instead, so this
  // catches both.
  // Either way, resource() is the branch key that the key store was reading, and awsErrorCode() is
  // DynamoDB's error code.
  private static void awsExceptionFromYourOwnKeyStore(
    DynamoDbClient dynamoDbClient,
    String tableName
  ) {
    PutItemRequest write = PutItemRequest
      .builder()
      .tableName(tableName)
      .item(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS("CustomKeyStoreErrorsExample"),
          SORT_KEY,
          AttributeValue.fromN("0"),
          ENCRYPTED_ATTRIBUTE,
          AttributeValue.fromS("encrypt and sign me!")
        )
      )
      .build();
    try {
      dynamoDbClient.putItem(write);
    } catch (ResourceNotFoundException | AccessDeniedException exception) {
      if (exception.resource() instanceof BranchKeyResource branchKey) {
        System.err.println(
          "The key store failed with " +
          exception.awsErrorCode() +
          " while reading the branch key " +
          branchKey.id() +
          ". Check the key store's own tables and permissions."
        );
        return;
      }
      throw exception;
    }
    throw new IllegalStateException(
      "A write whose key store wrote to a missing table succeeded"
    );
  }

  public static void main(String[] args) {
    if (args.length < 5) {
      throw new IllegalArgumentException(
        "To run this example, include the tableName, branchKeyId, keyStoreTableName, " +
        "logicalKeyStoreName and kmsKeyArn in args"
      );
    }
    customKeyStoreErrors(args[0], args[1], args[2], args[3], args[4]);
  }
}
