package software.amazon.cryptography.dbesdk.examples;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.cryptography.dbesdk.dynamodbencryption.DynamoDbEncryption;
import software.amazon.cryptography.dbesdk.dynamodbencryption.EncryptedDataKeyDescription;

public class GetEncryptedDataKeyDescriptionExample {

  public static void getEncryptedDataKeyDescription(
    String tableName,
    String partitionKey,
    String partitionKeyVal,
    String sortKeyName,
    String sortKeyValue,
    String expectedKeyProviderId,
    String expectedKeyProviderInfo,
    String expectedBranchKeyId,
    String expectedBranchKeyVersion
  ) {
    // 1. Create a new AWS SDK DynamoDb client. This client will be used to get item from the
    // DynamoDB table.
    final DynamoDbClient ddb = DynamoDbClient.builder().build();

    // 2. Get item from the DynamoDB table. This item will be used to Get Encrypted DataKey
    // Description.
    final Map<String, AttributeValue> keyToGet = new HashMap<>();
    keyToGet.put(
      partitionKey,
      AttributeValue.builder().s(partitionKeyVal).build()
    );
    keyToGet.put(sortKeyName, AttributeValue.builder().n(sortKeyValue).build());
    final GetItemRequest request = GetItemRequest
      .builder()
      .tableName(tableName)
      .key(keyToGet)
      .build();
    final Map<String, AttributeValue> returnedItem = ddb
      .getItem(request)
      .item();
    if (returnedItem.isEmpty()) {
      System.out.format("No item found with the key %s!%n", partitionKey);
    }

    // 3. Describe the encrypted data keys on the item. You can pass either a whole DynamoDB item
    // (as here) or the raw header bytes; both return the list of data key descriptions.
    final List<EncryptedDataKeyDescription> descriptions =
      DynamoDbEncryption.getEncryptedDataKeyDescription(returnedItem);

    // Alternatively, pass the header bytes directly. The header lives in the "aws_dbe_head"
    // attribute:
    // String header_attribute = "aws_dbe_head";
    // byte[] header = returnedItem.get(header_attribute).b().asByteArray();
    // List<EncryptedDataKeyDescription> descriptions =
    // DynamoDbEncryption.getEncryptedDataKeyDescription(header);

    // Assert everything
    final EncryptedDataKeyDescription desc = descriptions.get(0);
    assert desc.keyProviderId().equals(expectedKeyProviderId);
    if (expectedKeyProviderId.startsWith("aws-kms")) {
      assert desc.keyProviderInfo().equals(expectedKeyProviderInfo);
    }
    if (desc.keyProviderId().equals("aws-kms-hierarchy")) {
      assert desc.branchKeyId().equals(expectedBranchKeyId);
      assert desc.branchKeyVersion().equals(expectedBranchKeyVersion);
    }
  }

  public static void main(final String[] args) {
    if (args.length < 9) {
      throw new IllegalArgumentException(
        "To run this example, include the tableName, partitionKey, partitionKeyVal, " +
        "sortKeyName, sortKeyValue, expectedKeyProviderId, expectedKeyProviderInfo, " +
        "expectedBranchKeyId and expectedBranchKeyVersion in args"
      );
    }
    final String tableName = args[0];
    final String partitionKey = args[1];
    final String partitionKeyVal = args[2];
    final String sortKeyName = args[3];
    final String sortKeyValue = args[4];
    final String expectedKeyProviderId = args[5];
    final String expectedKeyProviderInfo = args[6];
    final String expectedBranchKeyId = args[7];
    final String expectedBranchKeyVersion = args[8];
    getEncryptedDataKeyDescription(
      tableName,
      partitionKey,
      partitionKeyVal,
      sortKeyName,
      sortKeyValue,
      expectedKeyProviderId,
      expectedKeyProviderInfo,
      expectedBranchKeyId,
      expectedBranchKeyVersion
    );
  }
}
