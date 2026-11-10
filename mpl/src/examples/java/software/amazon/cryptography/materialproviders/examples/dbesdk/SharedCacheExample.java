// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.dbesdk;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.cache.CacheType;
import software.amazon.cryptography.materialproviders.cache.CryptographicMaterialsCache;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;

/**
 * Configures two tables, each with its own hierarchical keyring, around one shared branch key cache, so a branch key
 * fetched for one table serves the other without another KMS call. Counts KMS calls to show it.
 *
 * <p>Arguments: two tables, each with partition key {@code partition_key} (string) and sort key {@code sort_key}
 * (number); and the key store's table name, logical name, KMS key ARN in the SDK's default Region, and an existing
 * branch key id.
 */
public final class SharedCacheExample {

  private SharedCacheExample() {}

  public static void main(String[] args) {
    if (args.length != 6) {
      throw new IllegalArgumentException(
        "Arguments: <table-1> <table-2> <key-store-table> <logical-key-store-name> <kms-key-arn> <branch-key-id>"
      );
    }
    try (DynamoDbClient keyStoreDdbClient = DynamoDbClient.create()) {
      run(args[0], args[1], args[2], args[3], args[4], args[5], keyStoreDdbClient);
    }
  }

  public static void run(
    String table1,
    String table2,
    String keyStoreTableName,
    String logicalKeyStoreName,
    String kmsKeyArn,
    String branchKeyId,
    DynamoDbClient keyStoreDdbClient
  ) {
    // 1. A KMS client that counts its calls.
    AtomicInteger kmsCalls = new AtomicInteger();
    ExecutionInterceptor counter = new ExecutionInterceptor() {
      @Override
      public void afterExecution(Context.AfterExecution context, ExecutionAttributes executionAttributes) {
        kmsCalls.incrementAndGet();
      }
    };

    // 2. The shared cache. Keyrings share its entries only with equal partition ids and logical key store names.
    CacheType sharedCache = CacheType.shared(CryptographicMaterialsCache.create(CacheType.defaultCache(100)));
    String partitionId = "shared-cache-example";

    try (
      KmsClient kmsClient = KmsClient.builder().overrideConfiguration(o -> o.addExecutionInterceptor(counter)).build();
      BranchKeyStore keyStore1 = keyStore(
        keyStoreTableName,
        logicalKeyStoreName,
        kmsKeyArn,
        kmsClient,
        keyStoreDdbClient
      );
      BranchKeyStore keyStore2 = keyStore(
        keyStoreTableName,
        logicalKeyStoreName,
        kmsKeyArn,
        kmsClient,
        keyStoreDdbClient
      )
    ) {
      // 3. Each table is configured on its own, with its own key store object and keyring, both on the shared cache.
      Keyring keyring1 = keyring(keyStore1, branchKeyId, sharedCache, partitionId);
      Keyring keyring2 = keyring(keyStore2, branchKeyId, sharedCache, partitionId);

      try (
        DynamoDbClient ddbClient1 = encryptingClient(table1, keyring1);
        DynamoDbClient ddbClient2 = encryptingClient(table2, keyring2)
      ) {
        // 4. Put and get an item in the first table; its keyring fetches the branch key and caches it.
        putAndGet(ddbClient1, table1);
        if (kmsCalls.get() == 0) {
          throw new IllegalStateException("The first table's keyring did not call KMS");
        }

        // 5. The second table's keyring finds the branch key in the shared cache, so it calls KMS no more.
        int before = kmsCalls.get();
        putAndGet(ddbClient2, table2);
        if (kmsCalls.get() != before) {
          throw new IllegalStateException("The second table's keyring called KMS despite the shared cache");
        }
      }
    }
  }

  private static Keyring keyring(BranchKeyStore keyStore, String branchKeyId, CacheType cache, String partitionId) {
    return AwsKmsHierarchicalKeyring
      .builder()
      .keyStore(keyStore)
      .branchKeyId(branchKeyId)
      .ttl(Duration.ofMinutes(10))
      .cache(cache)
      .partitionId(partitionId)
      .build();
  }

  private static BranchKeyStore keyStore(
    String tableName,
    String logicalKeyStoreName,
    String kmsKeyArn,
    KmsClient kmsClient,
    DynamoDbClient ddbClient
  ) {
    return BranchKeyStore
      .builder()
      .ddbTableName(tableName)
      .logicalKeyStoreName(logicalKeyStoreName)
      .kmsConfiguration(KmsConfiguration.kmsKeyArn(kmsKeyArn))
      .kmsClient(kmsClient)
      .ddbClient(ddbClient)
      .build();
  }

  // A DynamoDB client that encrypts and decrypts the table's items with the keyring.
  private static DynamoDbClient encryptingClient(String tableName, Keyring keyring) {
    ItemEncryptionSchema schema = ItemEncryptionSchema
      .builder()
      .partitionKeyName("partition_key")
      .sortKeyName("sort_key")
      .encryptAndSign("sensitive_data")
      .build();
    DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .logicalTableName(tableName)
      .schema(schema)
      .keyring(keyring)
      .build();
    DynamoDbEncryptionInterceptor interceptor = DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();
    return DynamoDbClient.builder().overrideConfiguration(o -> o.addExecutionInterceptor(interceptor)).build();
  }

  private static void putAndGet(DynamoDbClient ddbClient, String tableName) {
    Map<String, AttributeValue> key = new HashMap<>();
    key.put("partition_key", AttributeValue.builder().s("SharedCacheExample").build());
    key.put("sort_key", AttributeValue.builder().n("0").build());
    Map<String, AttributeValue> item = new HashMap<>(key);
    item.put("sensitive_data", AttributeValue.builder().s("encrypt and sign me!").build());
    ddbClient.putItem(b -> b.tableName(tableName).item(item));
    Map<String, AttributeValue> returned = ddbClient
      .getItem(b -> b.tableName(tableName).key(key).consistentRead(true))
      .item();
    if (!"encrypt and sign me!".equals(returned.get("sensitive_data").s())) {
      throw new IllegalStateException("The item in " + tableName + " did not decrypt to what was put");
    }
  }
}
