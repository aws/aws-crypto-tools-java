// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.dbesdk;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.cache.CacheType;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;

/**
 * Customer example (HierarchicalKeyringExample): a hierarchical keyring with one branch key per tenant,
 * chosen from the item's partition key by a DynamoDB-key branch key id supplier.
 * Tenants are separated by partition, so a tenant cannot make the keyring use another tenant's branch key.
 */
public final class HierarchicalKeyringExample {

  private HierarchicalKeyringExample() {}

  /**
   * @param ddb the client for the key store table; with real AWS, leave it out and the store makes one
   * @param kms the client for {@code kmsKeyArn}; with real AWS, leave it out and the store makes one
   * @return the two tenants' encrypted items
   */
  public static List<Map<String, String>> encryptAndDecryptForTwoTenants(
    DynamoDbClient ddb,
    KmsClient kms,
    String keyStoreTableName,
    String logicalKeyStoreName,
    String kmsKeyArn
  ) {
    // With real AWS: BranchKeyStore.builder().ddbTableName(...).logicalKeyStoreName(...)
    //   .kmsConfiguration(KmsConfiguration.kmsKeyArn(kmsKeyArn)).build()
    try (
      BranchKeyStore keyStore = BranchKeyStore
        .builder()
        .ddbTableName(keyStoreTableName)
        .logicalKeyStoreName(logicalKeyStoreName)
        .kmsConfiguration(KmsConfiguration.kmsKeyArn(kmsKeyArn))
        .ddbClient(ddb)
        .kmsClient(kms)
        .build()
    ) {
      // Key store administration, usually done once outside the application.
      keyStore.createKeyStore();
      String tenant1BranchKeyId = keyStore.createKey().branchKeyIdentifier();
      String tenant2BranchKeyId = keyStore.createKey().branchKeyIdentifier();

      DdbKeyBranchKeyIdSupplier byTenant = ddbKey -> {
        String tenant = ddbKey.get(ExampleItems.PARTITION_KEY);
        if ("tenant1Id".equals(tenant)) {
          return tenant1BranchKeyId;
        }
        if ("tenant2Id".equals(tenant)) {
          return tenant2BranchKeyId;
        }
        throw new IllegalArgumentException("Item does not contain valid tenant ID");
      };
      AwsKmsHierarchicalKeyring keyring = AwsKmsHierarchicalKeyring
        .builder()
        .keyStore(keyStore)
        .branchKeyIdSupplier(DdbKeyBranchKeyIdSupplier.asBranchKeyIdSupplier(byTenant))
        // How long a branch key is used before the keyring asks KMS again.
        .ttl(Duration.ofMinutes(10))
        // How many branch keys the keyring holds.
        .cache(CacheType.defaultCache(100))
        .build();

      DbEsdkLikeItemEncryptor encryptor = ExampleItems.encryptor(keyring);
      List<Map<String, String>> encrypted = new ArrayList<>();
      encrypted.add(ExampleItems.roundTrip(encryptor, ExampleItems.item("tenant1Id")));
      encrypted.add(ExampleItems.roundTrip(encryptor, ExampleItems.item("tenant2Id")));
      return encrypted;
    }
  }
}
