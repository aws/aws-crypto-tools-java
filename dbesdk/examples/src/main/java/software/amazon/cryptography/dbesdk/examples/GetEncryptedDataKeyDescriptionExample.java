package software.amazon.cryptography.dbesdk.examples;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.EncryptedDataKeyDescription;

public class GetEncryptedDataKeyDescriptionExample {

  public static void getEncryptedDataKeyDescription(
    String tableName,
    String partitionKey,
    String partitionKeyValue,
    String sortKeyName,
    String sortKeyValue,
    String expectedKeyProviderId,
    String expectedKeyProviderInfo,
    String expectedBranchKeyId,
    String expectedBranchKeyVersion
  ) {
    // 1. Create a new AWS SDK DynamoDB client. This client will be used to get item from the
    // DynamoDB table.
    try (
      DynamoDbClient dynamoDbClient = DynamoDbClient.builder().build()
    ) {
      // 2. Get item from the DynamoDB table. This item will be used to Get Encrypted DataKey
      // Description.
      final Map<String, AttributeValue> keyToGet = new HashMap<>();
      keyToGet.put(
        partitionKey,
        AttributeValue.builder().s(partitionKeyValue).build()
      );
      keyToGet.put(sortKeyName, AttributeValue.builder().n(sortKeyValue).build());
      final GetItemRequest request = GetItemRequest
        .builder()
        .tableName(tableName)
        .key(keyToGet)
        .build();
      final Map<String, AttributeValue> returnedItem = dynamoDbClient
        .getItem(request)
        .item();
      if (returnedItem.isEmpty()) {
        System.out.format("No item found with the key %s!%n", partitionKey);
      }

      // 3. Describe the encrypted data keys on the item. You can read them from a whole DynamoDB
      // item (fromItem, as here) or from the raw header bytes (fromHeader); both return the list of
      // data key descriptions.
      final List<EncryptedDataKeyDescription> descriptions =
        EncryptedDataKeyDescription.fromItem(returnedItem);

      // Alternatively, pass the header bytes directly. The header lives in the "aws_dbe_head"
      // attribute:
      // String headerAttribute = "aws_dbe_head";
      // byte[] header = returnedItem.get(headerAttribute).b().asByteArray();
      // List<EncryptedDataKeyDescription> descriptions =
      //   EncryptedDataKeyDescription.fromHeader(header);

      // Assert that the first data key description matches the expected key provider ID, the key
      // provider info (for AWS KMS keyrings), and the branch key ID and version (for the
      // hierarchical keyring).
      final EncryptedDataKeyDescription description = descriptions.get(0);
      assert description.keyProviderId().equals(expectedKeyProviderId);
      if (expectedKeyProviderId.startsWith("aws-kms")) {
        assert description.keyProviderInfo().equals(expectedKeyProviderInfo);
      }
      if (description.keyProviderId().equals("aws-kms-hierarchy")) {
        assert description.branchKeyId().equals(expectedBranchKeyId);
        assert description.branchKeyVersion().equals(expectedBranchKeyVersion);
      }
    }
  }

  public static void main(final String[] args) {
    if (args.length < 9) {
      throw new IllegalArgumentException(
        "To run this example, include the tableName, partitionKey, partitionKeyValue, " +
        "sortKeyName, sortKeyValue, expectedKeyProviderId, expectedKeyProviderInfo, " +
        "expectedBranchKeyId and expectedBranchKeyVersion in args"
      );
    }
    final String tableName = args[0];
    final String partitionKey = args[1];
    final String partitionKeyValue = args[2];
    final String sortKeyName = args[3];
    final String sortKeyValue = args[4];
    final String expectedKeyProviderId = args[5];
    final String expectedKeyProviderInfo = args[6];
    final String expectedBranchKeyId = args[7];
    final String expectedBranchKeyVersion = args[8];
    getEncryptedDataKeyDescription(
      tableName,
      partitionKey,
      partitionKeyValue,
      sortKeyName,
      sortKeyValue,
      expectedKeyProviderId,
      expectedKeyProviderInfo,
      expectedBranchKeyId,
      expectedBranchKeyVersion
    );
  }
}
