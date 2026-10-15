// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.cache.CacheType;
import software.amazon.cryptography.mpl.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.mpl.keyrings.AwsKmsHierarchicalKeyring;
import software.amazon.cryptography.mpl.keyrings.BranchKeyIdSupplier;
import software.amazon.cryptography.mpl.keystore.BranchKeyStore;
import software.amazon.cryptography.mpl.keystore.KmsConfiguration;

/**
 * Pattern (b): a branch key per tenant, chosen from the encryption context by a lambda,
 * with the key store administered from customer code (create the table, create keys, rotate one).
 * ESDK examples: AwsKmsHierarchicalKeyringExample, ExampleBranchKeyIdSupplier, and the key store admin calls they make.
 */
public final class HierarchicalKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private HierarchicalKeyringExample() {}

  /**
   * @param kmsClient real AWS: {@code KmsClient.create()}, or leave it out and the store creates one for the key's Region
   * @param ddbClient real AWS: {@code DynamoDbClient.create()}; the example also needs it to wait for the new table
   */
  public static void encryptAndDecrypt(
    String keyStoreTableName,
    String logicalKeyStoreName,
    String kmsKeyArn,
    KmsClient kmsClient,
    DynamoDbClient ddbClient
  ) {
    try (
      BranchKeyStore keyStore = BranchKeyStore
        .builder()
        .ddbTableName(keyStoreTableName)
        .logicalKeyStoreName(logicalKeyStoreName)
        .kmsConfiguration(KmsConfiguration.kmsKeyArn(kmsKeyArn))
        .kmsClient(kmsClient)
        .ddbClient(ddbClient)
        .build()
    ) {
      // Admin, usually done once by an operator: the table, then one branch key per tenant.
      keyStore.createKeyStore();
      // createKeyStore does not wait for a new table to become active; writes to it fail until then.
      ddbClient.waiter().waitUntilTableExists(table -> table.tableName(keyStoreTableName));
      String branchKeyIdA = keyStore.createKey();
      String branchKeyIdB = keyStore.createKey();

      BranchKeyIdSupplier byTenant = encryptionContext -> {
        String tenant = encryptionContext.get("tenant");
        if ("TenantA".equals(tenant)) {
          return branchKeyIdA;
        }
        if ("TenantB".equals(tenant)) {
          return branchKeyIdB;
        }
        throw new IllegalArgumentException("Encryption context has no known tenant");
      };
      Keyring keyring = AwsKmsHierarchicalKeyring
        .builder()
        .keyStore(keyStore)
        .branchKeyIdSupplier(byTenant)
        .ttlSeconds(600)
        .cache(CacheType.defaultCache(100))
        .build();

      EsdkLikeClient crypto = EsdkLikeClient.builder().build();
      Map<String, String> contextA = context("TenantA");
      Map<String, String> contextB = context("TenantB");
      byte[] ciphertextA = crypto.encryptData(keyring, EXAMPLE_DATA, contextA);
      byte[] ciphertextB = crypto.encryptData(keyring, EXAMPLE_DATA, contextB);

      // A keyring fixed to tenant A's branch key cannot read tenant B's message.
      Keyring onlyA = AwsKmsHierarchicalKeyring.builder().keyStore(keyStore).branchKeyId(branchKeyIdA).ttlSeconds(600).build();
      Expect.failure(NoMatchingDataKeyException.class, () -> crypto.decryptData(onlyA, ciphertextB));
      Expect.equal(EXAMPLE_DATA, crypto.decryptData(onlyA, ciphertextA).getResult());
      Expect.equal(EXAMPLE_DATA, crypto.decryptData(keyring, ciphertextB).getResult());

      // Rotation: a new active version for tenant A. Earlier messages still decrypt;
      // keyrings pick up the new version when their cached copy expires (here: a keyring that caches nothing).
      String versionBefore = keyStore.getActiveBranchKey(branchKeyIdA).branchKeyVersion();
      keyStore.versionKey(branchKeyIdA);
      Expect.isTrue(!versionBefore.equals(keyStore.getActiveBranchKey(branchKeyIdA).branchKeyVersion()), "a new active version");
      Keyring uncached = AwsKmsHierarchicalKeyring
        .builder()
        .keyStore(keyStore)
        .branchKeyIdSupplier(byTenant)
        .ttlSeconds(600)
        .cache(CacheType.noCache())
        .build();
      byte[] afterRotation = crypto.encryptData(uncached, EXAMPLE_DATA, contextA);
      Expect.equal(EXAMPLE_DATA, crypto.decryptData(uncached, ciphertextA).getResult());
      Expect.equal(EXAMPLE_DATA, crypto.decryptData(keyring, afterRotation).getResult());
    }
  }

  private static Map<String, String> context(String tenant) {
    Map<String, String> encryptionContext = new HashMap<>();
    encryptionContext.put("tenant", tenant);
    encryptionContext.put("encryption", "context");
    return encryptionContext;
  }
}
