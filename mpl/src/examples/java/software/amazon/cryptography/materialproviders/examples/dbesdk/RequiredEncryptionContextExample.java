// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.dbesdk;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import software.amazon.cryptography.materialproviders.examples.dbesdk.DbEsdkLikeItemEncryptor.CryptoAction;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;
import software.amazon.cryptography.materialproviders.keyrings.BranchKeyIdSupplier;
import software.amazon.cryptography.materialproviders.keyrings.GetBranchKeyIdResponse;
import software.amazon.cryptography.materialproviders.keystore.DynamoDbKeyStore;

/**
 * Customer example: a SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT attribute.
 * The attribute's value joins the encryption context as {@code aws-crypto-attr.tenant}, so keyrings can use it:
 * here a branch key id supplier picks the tenant's branch key from it.
 * Such a table is version 2, so the key attributes are SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT as well.
 * The header stores none of these entries; decrypt rebuilds them from the item,
 * so an item whose sort key was changed no longer matches the context its data key was wrapped under.
 */
public final class RequiredEncryptionContextExample {

  /** The attribute that names the tenant. */
  public static final String TENANT = "tenant";

  private RequiredEncryptionContextExample() {}

  /**
   * @param keyStore a key store whose table exists
   * @return a tenant item, encrypted
   */
  public static Map<String, String> encryptAndDecrypt(DynamoDbKeyStore keyStore) {
    DbEsdkLikeItemEncryptor encryptor = tenantTable(keyStore);
    return ExampleItems.roundTrip(encryptor, tenantItem("tenantA"));
  }

  /**
   * Edits the plaintext sort key of an encrypted item; the tenant, and so the branch key, stays the same.
   *
   * @return what decrypt throws
   */
  public static RuntimeException decryptAfterChangingSortKey(DynamoDbKeyStore keyStore) {
    DbEsdkLikeItemEncryptor encryptor = tenantTable(keyStore);
    Map<String, String> encrypted = encryptor.encryptItem(tenantItem("tenantA"));
    Map<String, String> moved = new LinkedHashMap<>(encrypted);
    moved.put(ExampleItems.SORT_KEY, "1");
    try {
      encryptor.decryptItem(moved);
    } catch (RuntimeException e) {
      return e;
    }
    throw new IllegalStateException("An item with a changed sort key decrypted");
  }

  private static DbEsdkLikeItemEncryptor tenantTable(DynamoDbKeyStore keyStore) {
    Map<String, String> branchKeyIds = new LinkedHashMap<>();
    branchKeyIds.put("tenantA", keyStore.createKey().branchKeyIdentifier());
    branchKeyIds.put("tenantB", keyStore.createKey().branchKeyIdentifier());
    // The MPL supplier sees the whole encryption context, including the SIGN_AND_INCLUDE entries.
    BranchKeyIdSupplier byTenant = request -> {
      String tenant = request.encryptionContext().get(DbEsdkLikeItemEncryptor.ATTR_PREFIX + TENANT);
      return GetBranchKeyIdResponse.builder().branchKeyId(branchKeyIds.get(tenant)).build();
    };
    AwsKmsHierarchicalKeyring keyring = AwsKmsHierarchicalKeyring.builder().keyStore(keyStore).branchKeyIdSupplier(byTenant).ttl(Duration.ofMinutes(10)).build();

    Map<String, CryptoAction> actions = ExampleItems.actions();
    actions.put(ExampleItems.PARTITION_KEY, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
    actions.put(ExampleItems.SORT_KEY, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
    actions.put(TENANT, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
    return DbEsdkLikeItemEncryptor
      .builder()
      .logicalTableName(ExampleItems.TABLE)
      .partitionKeyName(ExampleItems.PARTITION_KEY)
      .sortKeyName(ExampleItems.SORT_KEY)
      .attributeActionsOnEncrypt(actions)
      .keyring(keyring)
      .build();
  }

  private static Map<String, String> tenantItem(String tenant) {
    Map<String, String> item = ExampleItems.item("requiredEncryptionContextItem");
    item.put(TENANT, tenant);
    return item;
  }
}
