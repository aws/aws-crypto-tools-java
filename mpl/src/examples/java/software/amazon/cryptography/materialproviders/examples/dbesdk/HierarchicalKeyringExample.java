// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.dbesdk;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BranchKeyIdRequest;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemBranchKeyIdSupplier;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.cache.CacheType;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;

/**
 * Encrypts each tenant's items under that tenant's branch key, with a hierarchical keyring whose branch key id
 * supplier reads the tenant from the item's partition key.
 *
 * <p>Arguments: a table whose partition key is {@code partition_key} (string) and sort key is {@code sort_key}
 * (number); the key store's table name, logical name, and KMS key ARN in the SDK's default Region; and two existing
 * branch key ids, one per tenant. An operator creates them once, as the ESDK HierarchicalKeyringExample does.
 */
public final class HierarchicalKeyringExample {

  private HierarchicalKeyringExample() {}

  public static void main(String[] args) {
    if (args.length != 6) {
      throw new IllegalArgumentException(
        "Arguments: <table-name> <key-store-table> <logical-key-store-name> <kms-key-arn> " +
        "<tenant1-branch-key-id> <tenant2-branch-key-id>"
      );
    }
    try (KmsClient kmsClient = KmsClient.create(); DynamoDbClient keyStoreDdbClient = DynamoDbClient.create()) {
      run(args[0], args[1], args[2], args[3], args[4], args[5], kmsClient, keyStoreDdbClient);
    }
  }

  public static void run(
    String tableName,
    String keyStoreTableName,
    String logicalKeyStoreName,
    String kmsKeyArn,
    String tenant1BranchKeyId,
    String tenant2BranchKeyId,
    KmsClient kmsClient,
    DynamoDbClient keyStoreDdbClient
  ) {
    // 1. Configure the key store. Its DynamoDB client must not have the encryption interceptor.
    try (
      BranchKeyStore keyStore = BranchKeyStore
        .builder()
        .ddbTableName(keyStoreTableName)
        .logicalKeyStoreName(logicalKeyStoreName)
        .kmsConfiguration(KmsConfiguration.kmsKeyArn(kmsKeyArn))
        .kmsClient(kmsClient)
        .ddbClient(keyStoreDdbClient)
        .build()
    ) {
      // 2. Create the hierarchical keyring.
      // The supplier chooses the branch key from the item's partition key, which holds the tenant id.
      // The TTL bounds how long a cached branch key is used before the keyring asks KMS again.
      Keyring keyring = AwsKmsHierarchicalKeyring
        .builder()
        .keyStore(keyStore)
        .branchKeyIdSupplier(new TenantBranchKeyIdSupplier(tenant1BranchKeyId, tenant2BranchKeyId))
        .ttl(Duration.ofMinutes(10))
        .cache(CacheType.defaultCache(100))
        .build();

      // 3. Configure the table, and a DynamoDB client that encrypts and decrypts its items.
      ItemEncryptionSchema schema = ItemEncryptionSchema
        .builder()
        .partitionKeyName("partition_key")
        .sortKeyName("sort_key")
        .encryptAndSign("tenant_sensitive_data")
        .doNothingPrefix(":")
        .build();
      DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
        .builder()
        .tableName(tableName)
        .logicalTableName(tableName)
        .schema(schema)
        .keyring(keyring)
        .build();
      DynamoDbEncryptionInterceptor interceptor = DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();
      try (
        DynamoDbClient ddbClient = DynamoDbClient
          .builder()
          .overrideConfiguration(o -> o.addExecutionInterceptor(interceptor))
          .build()
      ) {
        // 4. Put and get an item for each tenant.
        for (String tenant : new String[] { "tenant1", "tenant2" }) {
          Map<String, AttributeValue> item = key(tenant);
          item.put("tenant_sensitive_data", AttributeValue.builder().s("data of " + tenant).build());
          ddbClient.putItem(b -> b.tableName(tableName).item(item));
          Map<String, AttributeValue> returned = ddbClient
            .getItem(b -> b.tableName(tableName).key(key(tenant)).consistentRead(true))
            .item();
          if (!("data of " + tenant).equals(returned.get("tenant_sensitive_data").s())) {
            throw new IllegalStateException("The item of " + tenant + " did not decrypt to what was put");
          }
        }
      }
    }
  }

  /** Maps the tenant id in an item's partition key to that tenant's branch key. */
  static final class TenantBranchKeyIdSupplier implements ItemBranchKeyIdSupplier {

    private final String tenant1BranchKeyId;
    private final String tenant2BranchKeyId;

    TenantBranchKeyIdSupplier(String tenant1BranchKeyId, String tenant2BranchKeyId) {
      this.tenant1BranchKeyId = tenant1BranchKeyId;
      this.tenant2BranchKeyId = tenant2BranchKeyId;
    }

    // The request's attributes always hold the item's primary key.
    @Override
    public String getBranchKeyId(BranchKeyIdRequest request) {
      String tenant = request.attributes().get("partition_key").s();
      if ("tenant1".equals(tenant)) {
        return tenant1BranchKeyId;
      }
      if ("tenant2".equals(tenant)) {
        return tenant2BranchKeyId;
      }
      throw new IllegalArgumentException("The item has no known tenant");
    }
  }

  private static Map<String, AttributeValue> key(String tenant) {
    Map<String, AttributeValue> key = new HashMap<>();
    key.put("partition_key", AttributeValue.builder().s(tenant).build());
    key.put("sort_key", AttributeValue.builder().n("0").build());
    return key;
  }
}
