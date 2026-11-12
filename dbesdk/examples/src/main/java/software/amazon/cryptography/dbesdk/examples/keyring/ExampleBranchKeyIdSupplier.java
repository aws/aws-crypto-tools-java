package software.amazon.cryptography.dbesdk.examples.keyring;

import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BranchKeyIdRequest;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemBranchKeyIdSupplier;

/**
 * Used in the {@code HierarchicalKeyringExample}. In that example, we have a table where we
 * distinguish multiple tenants by a tenant ID that is stored in our partition attribute. The
 * expectation is that this does not produce a confused deputy because the tenants are separated by
 * partition. In order to create a Hierarchical Keyring that is capable of encrypting or decrypting
 * data for either tenant, we implement this interface to map the correct branch key ID to the
 * correct tenant ID.
 */
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
   * <p>{@code request.attributes()} holds the item's partition key, its sort key if the table has
   * one, and every attribute the schema lists as {@code signAndIncludeInEncryptionContext}. The
   * request also carries the table name and the key attribute names; this example reads only the
   * partition key, which holds the tenant ID.
   */
  @Override
  public String getBranchKeyId(BranchKeyIdRequest request) {
    AttributeValue partitionKey = request.attributes().get("partition_key");
    if (partitionKey == null) {
      throw new IllegalArgumentException(
        "Item invalid, does not contain expected partition key attribute."
      );
    }
    String tenantId = partitionKey.s();
    // A partition key that is not a string has no s() value. Switching on null would throw
    // NullPointerException, so report it as an invalid tenant ID instead.
    if (tenantId == null) {
      throw new IllegalArgumentException(
        "Item does not contain valid tenant ID"
      );
    }
    return switch (tenantId) {
      case "tenant1Id" -> branchKeyIdForTenant1;
      case "tenant2Id" -> branchKeyIdForTenant2;
      default -> throw new IllegalArgumentException(
        "Item does not contain valid tenant ID"
      );
    };
  }
}
