package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling;

import java.time.Duration;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemBranchKeyIdSupplier;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.CustomComponentException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.ServiceException;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;

/**
 * Shows what the DB-ESDK throws when a branch key ID supplier that you implemented fails.
 *
 * <p>When a component that you implemented throws, its exception arrives as the cause of a {@link
 * CustomComponentException}, whose {@code resource()} names the component.
 *
 * <p>When your component throws an AWS SDK exception or a materialproviders exception, the DB-ESDK
 * reports it with that exception's kind instead, so a throttled call stays retryable.
 *
 * <p>A DynamoDB conditional check that fails inside your component is a {@code ServiceException}
 * whose {@code awsErrorCode()} is {@code ConditionalCheckFailedException}, and is not retryable.
 *
 * <p>Running this example needs AWS credentials, a key store with a branch key in it, and a
 * DynamoDB table with partition key "partition_key" (S) and sort key "sort_key" (N). It writes one
 * plaintext item to the table.
 */
public class CustomBranchKeyIdSupplierErrorsExample {

  private static final String PARTITION_KEY = "partition_key";
  private static final String SORT_KEY = "sort_key";
  private static final String ENCRYPTED_ATTRIBUTE = "attribute1";

  public static void customBranchKeyIdSupplierErrors(
    String tableName,
    String branchKeyId,
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
      ItemEncryptionSchema schema = ItemEncryptionSchema
        .builder()
        .partitionKeyName(PARTITION_KEY)
        .sortKeyName(SORT_KEY)
        .encryptAndSign(ENCRYPTED_ATTRIBUTE)
        .build();

      exceptionFromYourOwnSupplier(tableName, schema, branchKeyId, keyStore);
      failedConditionInYourOwnSupplier(
        tableName,
        schema,
        branchKeyId,
        keyStore
      );
    }
  }

  /** Thrown by this application's branch key ID supplier for a tenant that it does not know. */
  static final class UnknownTenantException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    UnknownTenantException(String tenantId) {
      super("No branch key for tenant " + tenantId);
    }
  }

  // An exception that your branch key ID supplier throws arrives as the cause of a
  // CustomComponentException, so test the cause for your own type.
  private static void exceptionFromYourOwnSupplier(
    String tableName,
    ItemEncryptionSchema schema,
    String branchKeyId,
    BranchKeyStore keyStore
  ) {
    ItemBranchKeyIdSupplier branchKeyIdSupplier = request -> {
      String tenantId = request.attributes().get(PARTITION_KEY).s();
      if (!"tenant1".equals(tenantId)) {
        throw new UnknownTenantException(tenantId);
      }
      return branchKeyId;
    };
    Keyring hierarchicalKeyring = AwsKmsHierarchicalKeyring
      .builder()
      .branchKeyIdSupplier(branchKeyIdSupplier)
      .keyStore(keyStore)
      .ttl(Duration.ofMinutes(10))
      .build();
    DynamoDbTableEncryptionConfig tableConfig = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .schema(schema)
      .keyring(hierarchicalKeyring)
      .build();
    DynamoDbEncryptionInterceptor encryptionInterceptor =
      DynamoDbEncryptionInterceptor.builder().tableConfigs(tableConfig).build();
    PutItemRequest tenant2Write = PutItemRequest
      .builder()
      .tableName(tableName)
      .item(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS("tenant2"),
          SORT_KEY,
          AttributeValue.fromN("0"),
          ENCRYPTED_ATTRIBUTE,
          AttributeValue.fromS("encrypt and sign me!")
        )
      )
      .build();

    try (
      DynamoDbClient dynamoDbClient = DynamoDbClient
        .builder()
        .overrideConfiguration(overrides ->
          overrides.addExecutionInterceptor(encryptionInterceptor)
        )
        .build()
    ) {
      dynamoDbClient.putItem(tenant2Write);
    } catch (CustomComponentException exception) {
      if (
        exception.getCause() instanceof UnknownTenantException unknownTenant
      ) {
        System.err.println(
          "This application has no branch key for the tenant: " +
          unknownTenant.getMessage()
        );
        return;
      }
      throw exception;
    }
    throw new IllegalStateException(
      "Writing an item for an unknown tenant succeeded"
    );
  }

  // Your component can make conditional DynamoDB writes of its own. When one fails, the DB-ESDK
  // reports it as a ServiceException with awsErrorCode() ConditionalCheckFailedException, which
  // is not retryable.
  // Here the supplier claims each tenant for this application with a write that fails if another
  // application holds the claim, and another application already does.
  private static void failedConditionInYourOwnSupplier(
    String tableName,
    ItemEncryptionSchema schema,
    String branchKeyId,
    BranchKeyStore keyStore
  ) {
    // The claim records are plaintext items in the same table, under a "claim#" partition key.
    PutItemRequest claimByAnotherApplication = PutItemRequest
      .builder()
      .tableName(tableName)
      .item(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS("claim#tenant3"),
          SORT_KEY,
          AttributeValue.fromN("0"),
          "claimed_by",
          AttributeValue.fromS("another-application")
        )
      )
      .build();
    PutItemRequest tenant3Write = PutItemRequest
      .builder()
      .tableName(tableName)
      .item(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS("tenant3"),
          SORT_KEY,
          AttributeValue.fromN("0"),
          ENCRYPTED_ATTRIBUTE,
          AttributeValue.fromS("encrypt and sign me!")
        )
      )
      .build();

    try (DynamoDbClient plaintextClient = DynamoDbClient.create()) {
      plaintextClient.putItem(claimByAnotherApplication);

      ItemBranchKeyIdSupplier claimingSupplier = request -> {
        String tenantId = request.attributes().get(PARTITION_KEY).s();
        PutItemRequest claimByThisApplication = PutItemRequest
          .builder()
          .tableName(tableName)
          .item(
            Map.of(
              PARTITION_KEY,
              AttributeValue.fromS("claim#" + tenantId),
              SORT_KEY,
              AttributeValue.fromN("0"),
              "claimed_by",
              AttributeValue.fromS("this-application")
            )
          )
          .conditionExpression(
            "attribute_not_exists(" + PARTITION_KEY + ") OR claimed_by = :me"
          )
          .expressionAttributeValues(
            Map.of(":me", AttributeValue.fromS("this-application"))
          )
          .build();
        plaintextClient.putItem(claimByThisApplication);
        return branchKeyId;
      };
      Keyring hierarchicalKeyring = AwsKmsHierarchicalKeyring
        .builder()
        .branchKeyIdSupplier(claimingSupplier)
        .keyStore(keyStore)
        .ttl(Duration.ofMinutes(10))
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
        dynamoDbClient.putItem(tenant3Write);
      }
    } catch (ServiceException exception) {
      // The supplier's own DynamoDB call failed, so awsErrorCode() is DynamoDB's code for it.
      if ("ConditionalCheckFailedException".equals(exception.awsErrorCode())) {
        System.err.println(
          "Another application already claimed this tenant. Do not retry; resolve the claim " +
          "first."
        );
        return;
      }
      throw exception;
    }
    throw new IllegalStateException(
      "A write for a tenant that another application claimed succeeded"
    );
  }

  public static void main(String[] args) {
    if (args.length < 5) {
      throw new IllegalArgumentException(
        "To run this example, include the tableName, branchKeyId, keyStoreTableName, " +
        "logicalKeyStoreName and kmsKeyArn in args"
      );
    }
    customBranchKeyIdSupplierErrors(
      args[0],
      args[1],
      args[2],
      args[3],
      args[4]
    );
  }
}
