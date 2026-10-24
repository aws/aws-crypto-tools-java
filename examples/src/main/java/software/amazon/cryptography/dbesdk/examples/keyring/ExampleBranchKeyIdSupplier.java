package software.amazon.cryptography.dbesdk.examples.keyring;

import java.util.Map;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbesdk.dynamodbencryption.DynamoDbKeyBranchKeyIdSupplier;

// Used in the 'HierarchicalKeyringExample'.
// In that example, we have a table where we distinguish multiple tenants
// by a tenant ID that is stored in our partition attribute.
// The expectation is that this does not produce a confused deputy
// because the tenants are separated by partition.
// In order to create a Hierarchical Keyring that is capable of encrypting or
// decrypting data for either tenant, we implement this interface
// to map the correct branch key ID to the correct tenant ID.
class ExampleBranchKeyIdSupplier implements DynamoDbKeyBranchKeyIdSupplier {

  private final String branchKeyIdForTenant1;
  private final String branchKeyIdForTenant2;

  public ExampleBranchKeyIdSupplier(String tenant1Id, String tenant2Id) {
    this.branchKeyIdForTenant1 = tenant1Id;
    this.branchKeyIdForTenant2 = tenant2Id;
  }

  @Override
  public String getBranchKeyIdFromDdbKey(Map<String, AttributeValue> ddbKey) {
    if (!ddbKey.containsKey("partition_key")) {
      throw new IllegalArgumentException(
        "Item invalid, does not contain expected partition key attribute."
      );
    }
    final String tenantKeyId = ddbKey.get("partition_key").s();

    final String branchKeyId;
    if (tenantKeyId.equals("tenant1Id")) {
      branchKeyId = branchKeyIdForTenant1;
    } else if (tenantKeyId.equals("tenant2Id")) {
      branchKeyId = branchKeyIdForTenant2;
    } else {
      throw new IllegalArgumentException(
        "Item does not contain valid tenant ID"
      );
    }
    return branchKeyId;
  }
}
