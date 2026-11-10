// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.cache.CacheType;
import software.amazon.cryptography.materialproviders.cache.CryptographicMaterialsCache;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;

/**
 * Shares one branch key cache between hierarchical keyrings, so a branch key one keyring fetched serves the others
 * without another KMS call. Counts KMS calls to show it.
 *
 * <p>Arguments: the key store's table name, its logical name, the ARN of its KMS key in the SDK's default Region, and
 * the id of an existing branch key. Calls DynamoDB GetItem and KMS Decrypt.
 */
public final class SharedCacheExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private SharedCacheExample() {}

  public static void main(String[] args) {
    if (args.length != 4) {
      throw new IllegalArgumentException(
        "Arguments: <key-store-table> <logical-key-store-name> <kms-key-arn> <branch-key-id>"
      );
    }
    try (DynamoDbClient ddbClient = DynamoDbClient.create()) {
      run(args[0], args[1], args[2], args[3], ddbClient);
    }
  }

  public static void run(
    String keyStoreTableName,
    String logicalKeyStoreName,
    String kmsKeyArn,
    String branchKeyId,
    DynamoDbClient ddbClient
  ) {
    // 1. Instantiate the ESDK, and a KMS client that counts its calls.
    EsdkClient esdk = EsdkClient.create();
    Map<String, String> encryptionContext = Collections.singletonMap("encryption", "context");
    AtomicInteger kmsCalls = new AtomicInteger();
    ExecutionInterceptor counter = new ExecutionInterceptor() {
      @Override
      public void afterExecution(Context.AfterExecution context, ExecutionAttributes executionAttributes) {
        kmsCalls.incrementAndGet();
      }
    };

    // 2. Create the shared cache.
    // Keyrings that share it must also share a partition id; keyrings with other partition ids keep their own entries.
    CacheType sharedCache = CacheType.shared(CryptographicMaterialsCache.create(CacheType.defaultCache(100)));
    String partitionId = "shared-cache-example";

    try (
      KmsClient kmsClient = KmsClient.builder().overrideConfiguration(o -> o.addExecutionInterceptor(counter)).build();
      BranchKeyStore keyStore1 = keyStore(keyStoreTableName, logicalKeyStoreName, kmsKeyArn, kmsClient, ddbClient);
      BranchKeyStore keyStore2 = keyStore(keyStoreTableName, logicalKeyStoreName, kmsKeyArn, kmsClient, ddbClient)
    ) {
      // 3. Two keyrings, each with its own key store object for the same table and logical name.
      // Entries are shared only between key stores with equal logical names.
      Keyring keyring1 = keyring(keyStore1, branchKeyId, sharedCache, partitionId);
      Keyring keyring2 = keyring(keyStore2, branchKeyId, sharedCache, partitionId);

      // 4. Encrypt and decrypt with keyring1, which fetches the branch key and caches it.
      byte[] ciphertext = esdk
        .encrypt(b -> b.plaintext(EXAMPLE_DATA).keyring(keyring1).encryptionContext(encryptionContext))
        .ciphertext();
      requireExampleData(esdk.decrypt(b -> b.ciphertext(ciphertext).keyring(keyring1)).plaintext());
      if (kmsCalls.get() == 0) {
        throw new IllegalStateException("keyring1 did not call KMS");
      }

      // 5. keyring2 finds both entries in the shared cache, so it calls KMS no more.
      int before = kmsCalls.get();
      byte[] ciphertext2 = esdk
        .encrypt(b -> b.plaintext(EXAMPLE_DATA).keyring(keyring2).encryptionContext(encryptionContext))
        .ciphertext();
      requireExampleData(esdk.decrypt(b -> b.ciphertext(ciphertext2).keyring(keyring2)).plaintext());
      requireExampleData(esdk.decrypt(b -> b.ciphertext(ciphertext).keyring(keyring2)).plaintext());
      if (kmsCalls.get() != before) {
        throw new IllegalStateException("keyring2 called KMS despite the shared cache");
      }

      // 6. A keyring with another partition id does not see those entries, so it calls KMS again.
      Keyring otherPartition = keyring(keyStore2, branchKeyId, sharedCache, "another-partition");
      requireExampleData(esdk.decrypt(b -> b.ciphertext(ciphertext).keyring(otherPartition)).plaintext());
      if (kmsCalls.get() == before) {
        throw new IllegalStateException("A keyring with another partition id used the shared entries");
      }
    }
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

  private static void requireExampleData(byte[] plaintext) {
    if (!Arrays.equals(plaintext, EXAMPLE_DATA)) {
      throw new IllegalStateException("Decrypted plaintext does not match");
    }
  }
}
