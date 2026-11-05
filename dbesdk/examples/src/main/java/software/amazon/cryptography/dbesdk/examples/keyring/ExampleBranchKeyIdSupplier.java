package software.amazon.cryptography.dbesdk.examples.keyring;

import java.util.Map;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemBranchKeyIdSupplier;

// Used in the 'HierarchicalKeyringExample'.
// In that example, we have a table where we distinguish multiple tenants
// by a tenant ID that is stored in our partition attribute.
// The expectation is that this does not produce a confused deputy
// because the tenants are separated by partition.
// In order to create a Hierarchical Keyring that is capable of encrypting or
// decrypting data for either tenant, we implement this interface
// to map the correct branch key ID to the correct tenant ID.
class ExampleBranchKeyIdSupplier implements ItemBranchKeyIdSupplier {

  private final String branchKeyIdForTenant1;
  private final String branchKeyIdForTenant2;

  ExampleBranchKeyIdSupplier(
    String branchKeyIdForTenant1,
    String branchKeyIdForTenant2
  ) {
    this.branchKeyIdForTenant1 = branchKeyIdForTenant1;
    this.branchKeyIdForTenant2 = branchKeyIdForTenant2;
  }

  /**
   * Returns the branch key ID to use for the item being written or read.
   *
   * <p>{@code itemContext} always holds the item's partition key and, if the table has one, its
   * sort key. If the item's schema lists any attributes in its
   * {@code signAndIncludeInEncryptionContext} group, {@code itemContext} also holds each of those
   * attributes, plus three entries the DB-ESDK adds: {@code aws_dbe_table_name} (the table name),
   * {@code aws_dbe_partition_name} (the partition key's attribute name) and
   * {@code aws_dbe_sort_name} (the sort key's attribute name, present only if the table has a sort
   * key).
   *
   * <p>This example reads only the partition key, which holds the tenant ID.
   */
  @Override
  public String getBranchKeyId(Map<String, AttributeValue> itemContext) {
    final AttributeValue partitionKey = itemContext.get("partition_key");
    if (partitionKey == null) {
      throw new IllegalArgumentException(
        "Item invalid, does not contain expected partition key attribute."
      );
    }
    final String tenantId = partitionKey.s();

    final String branchKeyId;
    if ("tenant1Id".equals(tenantId)) {
      branchKeyId = branchKeyIdForTenant1;
    } else if ("tenant2Id".equals(tenantId)) {
      branchKeyId = branchKeyIdForTenant2;
    } else {
      throw new IllegalArgumentException(
        "Item does not contain valid tenant ID"
      );
    }
    return branchKeyId;
  }
}
