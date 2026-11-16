package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.EncryptedDataKeyDescription;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.cache.CacheType;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;

/**
 * This example writes an item encrypted with the Hierarchical Keyring, reads the stored item back
 * without decrypting it, and describes the encrypted data keys on it: which key provider wrapped
 * each data key and, for the Hierarchical Keyring, which branch key and branch key version.
 * Describing the data keys does not decrypt the item, so the read uses a plain DynamoDB client.
 * That step is its own method, {@link #describeEncryptedDataKeys(String, Map)}, which takes only a
 * table name and an item's primary key, so you can use it on items already in your table.
 *
 * <p>Running this example requires access to the DynamoDB Table whose name is provided in CLI arguments. This
 * table must be configured with the following primary key configuration:
 *   - Partition key is named "partition_key" with type (S)
 *   - Sort key is named "sort_key" with type (N)
 *
 * <p>It also requires a KeyStore with a branch key, and the KMS Key that protects that branch key.
 * See the "Create KeyStore Table Example" and "Create KeyStore Key Example" for how to create them.
 * You need the following access on the KMS Key:
 *   - GenerateDataKeyWithoutPlaintext
 *   - Decrypt
 */
public class GetEncryptedDataKeyDescriptionExample {

  public static void getEncryptedDataKeyDescription(
    String tableName,
    String branchKeyId,
    String keyStoreTableName,
    String logicalKeyStoreName,
    String kmsKeyArn
  ) {
    // 1. Configure your KeyStore resource. This SHOULD be the same configuration that you used to
    //    create the branch key. The DynamoDB and AWS KMS clients the keystore uses are optional;
    //    HierarchicalKeyringExample describes them. The try block closes them when it ends, so
    //    everything that uses the keystore stays inside it.
    try (
      DynamoDbClient keyStoreDynamoDbClient = DynamoDbClient.create();
      KmsClient keyStoreKmsClient = KmsClient.create()
    ) {
      BranchKeyStore keyStore = BranchKeyStore
        .builder()
        .ddbTableName(keyStoreTableName)
        .logicalKeyStoreName(logicalKeyStoreName)
        .kmsConfiguration(KmsConfiguration.kmsKeyArn(kmsKeyArn))
        .ddbClient(keyStoreDynamoDbClient)
        .kmsClient(keyStoreKmsClient)
        .build();

      // 2. Create a Hierarchical Keyring that uses this one branch key.
      Keyring hierarchicalKeyring = AwsKmsHierarchicalKeyring
        .builder()
        .keyStore(keyStore)
        .branchKeyId(branchKeyId)
        // This dictates how often we call back to KMS to authorize use of the branch key
        .ttl(Duration.ofSeconds(600))
        .cache(CacheType.defaultCache(100))
        .build();

      // 3. Decide how each attribute of the item is protected. BasicPutGetExample explains each
      //    action and the doNothing prefix.
      ItemEncryptionSchema schema = ItemEncryptionSchema
        .builder()
        .partitionKeyName("partition_key")
        .sortKeyName("sort_key")
        .encryptAndSign("sensitive_data")
        .doNothingPrefix(":")
        .build();

      // 4. Create the DynamoDB Encryption configuration for the table, and the interceptor.
      DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
        .builder()
        .tableName(tableName)
        .schema(schema)
        .keyring(hierarchicalKeyring)
        .build();
      DynamoDbEncryptionInterceptor encryptionInterceptor =
        DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();

      Map<String, AttributeValue> key = Map.of(
        "partition_key",
        AttributeValue.fromS(
          ExampleUtils.uniquePartitionKey("encryptedDataKeyDescriptionItem")
        ),
        "sort_key",
        AttributeValue.fromN("0")
      );

      // 5. Write an item with an encrypting DynamoDB client. The client encrypts the item
      //    client-side; its data key is wrapped by the branch key above.
      try (
        DynamoDbClient encryptingDynamoDbClient = DynamoDbClient
          .builder()
          .overrideConfiguration(overrides ->
            overrides.addExecutionInterceptor(encryptionInterceptor)
          )
          .build()
      ) {
        Map<String, AttributeValue> item = Map.of(
          "partition_key",
          key.get("partition_key"),
          "sort_key",
          key.get("sort_key"),
          "sensitive_data",
          AttributeValue.fromS("encrypt and sign me!")
        );
        encryptingDynamoDbClient.putItem(
          PutItemRequest.builder().tableName(tableName).item(item).build()
        );
      }

      // 6. Describe the encrypted data keys on the item just written. describeEncryptedDataKeys
      //    (below) needs only the table name and the item's primary key, so it works the same on
      //    any item already in the table, including ones written long ago or by other code.
      List<EncryptedDataKeyDescription> descriptions =
        describeEncryptedDataKeys(tableName, key);

      // The Hierarchical Keyring wraps the data key once, under the branch key.
      // hasAwsKmsKeyProviderId() is true when the key provider ID starts with "aws-kms", the prefix
      // every AWS KMS keyring writes; only then are keyProviderInfo and branchKeyId set.
      // hasAwsKmsHierarchyKeyProviderId() is true when the key provider ID is exactly
      // "aws-kms-hierarchy", which the Hierarchical Keyring writes; only then is branchKeyVersion
      // set, and only then does branchKeyId hold a branch key ID rather than a KMS key ARN.
      assert descriptions.size() == 1;
      EncryptedDataKeyDescription description = descriptions.get(0);
      assert description.hasAwsKmsHierarchyKeyProviderId();
      assert description.keyProviderInfo().equals(branchKeyId);
      assert description.branchKeyId().equals(branchKeyId);
      // The branch key version is the version of the branch key that was active when the item was
      // written. The keystore assigns it, so the example only checks that it is present.
      assert description.branchKeyVersion() != null;
    }
  }

  /**
   * Describes the encrypted data keys on an item already stored in a table, for example to find
   * which KMS key or branch key protects it. This needs no keyring and does not decrypt the item.
   *
   * @param tableName the table that holds the item
   * @param key the item's primary key
   * @return one description per encrypted data key on the item
   * @throws IllegalArgumentException if the table has no item with this key
   */
  public static List<EncryptedDataKeyDescription> describeEncryptedDataKeys(
    String tableName,
    Map<String, AttributeValue> key
  ) {
    // Read the stored item with a plain DynamoDB client. It returns the item as it is stored:
    // encrypted, with the item's header in its "aws_dbe_head" attribute.
    Map<String, AttributeValue> storedItem;
    try (DynamoDbClient plainDynamoDbClient = DynamoDbClient.create()) {
      storedItem =
        plainDynamoDbClient
          .getItem(
            GetItemRequest.builder().tableName(tableName).key(key).build()
          )
          .item();
    }
    if (storedItem.isEmpty()) {
      throw new IllegalArgumentException(
        "No item in " + tableName + " with key " + key
      );
    }

    // fromItem reads the encrypted data keys from a whole DynamoDB item, as here. If you only have
    // the item's header bytes (the binary value of its "aws_dbe_head" attribute),
    // EncryptedDataKeyDescription.fromHeader(byte[]) reads them from those instead.
    return EncryptedDataKeyDescription.fromItem(storedItem);
  }

  public static void main(String[] args) {
    if (args.length < 5) {
      throw new IllegalArgumentException(
        "To run this example, include the tableName, branchKeyId, keyStoreTableName, " +
        "logicalKeyStoreName and kmsKeyArn in args"
      );
    }
    String tableName = args[0];
    String branchKeyId = args[1];
    String keyStoreTableName = args[2];
    String logicalKeyStoreName = args[3];
    String kmsKeyArn = args[4];
    getEncryptedDataKeyDescription(
      tableName,
      branchKeyId,
      keyStoreTableName,
      logicalKeyStoreName,
      kmsKeyArn
    );
  }
}
