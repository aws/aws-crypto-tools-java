// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.cache.CacheType;
import software.amazon.cryptography.mpl.cache.CryptographicMaterialsCache;
import software.amazon.cryptography.mpl.keyrings.AwsKmsHierarchicalKeyring;
import software.amazon.cryptography.mpl.keystore.BranchKeyStore;
import software.amazon.cryptography.mpl.keystore.KmsConfiguration;

/**
 * Pattern (c): two hierarchical keyrings, each with its own key store object, share one branch key cache.
 * Equal partition ids and logical key store names let the second keyring use what the first one cached.
 * ESDK example: SharedCacheAcrossHierarchicalKeyringsExample.
 */
public final class SharedCacheExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private SharedCacheExample() {}

  /**
   * The key store table and {@code branchKeyId} exist already.
   * Real AWS: {@code KmsClient.create()} and {@code DynamoDbClient.create()} for the clients.
   */
  public static void encryptAndDecrypt(
    String keyStoreTableName,
    String logicalKeyStoreName,
    String partitionId,
    String kmsKeyArn,
    String branchKeyId,
    KmsClient kmsClient,
    DynamoDbClient ddbClient
  ) {
    CacheType sharedCache = CacheType.shared(CryptographicMaterialsCache.create(CacheType.defaultCache(100)));
    EsdkLikeClient crypto = EsdkLikeClient.builder().build();
    Map<String, String> encryptionContext = Collections.singletonMap("encryption", "context");

    try (
      BranchKeyStore keyStore1 = keyStore(keyStoreTableName, logicalKeyStoreName, kmsKeyArn, kmsClient, ddbClient);
      BranchKeyStore keyStore2 = keyStore(keyStoreTableName, logicalKeyStoreName, kmsKeyArn, kmsClient, ddbClient)
    ) {
      Keyring keyring1 = keyring(keyStore1, branchKeyId, sharedCache, partitionId);
      Keyring keyring2 = keyring(keyStore2, branchKeyId, sharedCache, partitionId);

      byte[] ciphertext1 = crypto.encryptData(keyring1, EXAMPLE_DATA, encryptionContext);
      Expect.equal(EXAMPLE_DATA, crypto.decryptData(keyring1, ciphertext1).getResult());
      // keyring2 finds both branch key entries keyring1 cached.
      byte[] ciphertext2 = crypto.encryptData(keyring2, EXAMPLE_DATA, encryptionContext);
      Expect.equal(EXAMPLE_DATA, crypto.decryptData(keyring2, ciphertext2).getResult());
    }
  }

  private static BranchKeyStore keyStore(String table, String logicalName, String kmsKeyArn, KmsClient kms, DynamoDbClient ddb) {
    return BranchKeyStore
      .builder()
      .ddbTableName(table)
      .logicalKeyStoreName(logicalName)
      .kmsConfiguration(KmsConfiguration.kmsKeyArn(kmsKeyArn))
      .kmsClient(kms)
      .ddbClient(ddb)
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
}
