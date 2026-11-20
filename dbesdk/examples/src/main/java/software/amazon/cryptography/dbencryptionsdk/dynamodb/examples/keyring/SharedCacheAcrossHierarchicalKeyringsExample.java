package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.keyring;

import java.time.Duration;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.cache.CacheType;
import software.amazon.cryptography.materialproviders.cache.CryptographicMaterialsCache;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;

/**
 * This example demonstrates how to use a shared cache across multiple Hierarchical Keyrings. With
 * this functionality, users only need to maintain one common shared cache across multiple
 * Hierarchical Keyrings with different Key Stores instances/KMS Clients/KMS Keys.
 *
 * <p>There are three important parameters that users need to carefully set while providing the shared
 * cache:
 *
 * <p>1. Partition ID - Partition ID is an optional parameter provided to the Hierarchical Keyring input,
 * which distinguishes Cryptographic Material Providers (i.e: Keyrings) writing to a cache.
 * - If the Partition ID is set and is the same for two Hierarchical Keyrings (or another Material Provider),
 *   they CAN share the same cache entries in the cache.
 * - If the Partition ID is set and is different for two Hierarchical Keyrings (or another Material Provider),
 *   they CANNOT share the same cache entries in the cache.
 * - If the Partition ID is not set by the user, it is initialized as a random 16-byte UUID which makes
 *   it unique for every Hierarchical Keyring, and two Hierarchical Keyrings (or another Material Provider)
 *   CANNOT share the same cache entries in the cache.
 *
 * <p>2. Logical Key Store Name - This parameter is set by the user when configuring the Key Store for
 * the Hierarchical Keyring. This is a logical name for the branch key store.
 * Suppose you have a physical Key Store (K). You create two instances of K (K1 and K2). Now, you create
 * two Hierarchical Keyrings (HK1 and HK2) with these Key Store instances (K1 and K2 respectively).
 * - If you want to share cache entries across these two keyrings, you should set the Logical Key Store Names
 *   for both the Key Store instances (K1 and K2) to be the same.
 * - If you set the Logical Key Store Names for K1 and K2 to be different, HK1 (which uses Key Store
 *   instance K1) and HK2 (which uses Key Store instance K2) will NOT be able to share cache
 *   entries.
 *
 * <p>3. Branch Key ID - Choose an effective Branch Key ID Schema
 *
 * <p>This is demonstrated in the example below. Notice that both K1 and K2 are instances of the same
 * physical Key Store (K). You MUST NEVER have two different physical Key Stores with the same Logical
 * Key Store Name.
 *
 * <p>Important Note: If you have two or more Hierarchy Keyrings with:
 * - Same Partition ID
 * - Same Logical Key Store Name of the Key Store for the Hierarchical Keyring
 * - Same Branch Key ID
 * then they WILL share the cache entries in the Shared Cache.
 * Please make sure that you set all of Partition ID, Logical Key Store Name and Branch Key ID
 * to be the same for two Hierarchical Keyrings if and only if you want them to share cache entries.
 *
 * <p>This example sets up DynamoDB Encryption for the AWS SDK client using the Hierarchical Keyring,
 * which establishes a key hierarchy where "branch" keys are persisted in DynamoDB. These branch keys
 * are used to protect your data keys, and these branch keys are themselves protected by a root KMS
 * Key.
 *
 * <p>This example first creates a shared cache that you can use across multiple Hierarchical Keyrings.
 * The example then configures a Hierarchical Keyring (HK1 and HK2) with the shared cache, a Branch
 * Key ID and two instances (K1 and K2) of the same physical Key Store (K) respectively, i.e. HK1 with
 * K1 and HK2 with K2. The example demonstrates that if you set the same Partition ID for HK1 and HK2,
 * the two keyrings can share cache entries. If you set different Partition ID of the Hierarchical
 * Keyrings, or different Logical Key Store Names of the Key Store instances, then the keyrings will
 * NOT be able to share cache entries.
 *
 * <p>Running this example requires access to the DynamoDB Table whose name is provided in CLI arguments. This
 * table must be configured with the following primary key configuration:
 *   - Partition key is named "partition_key" with type (S)
 *   - Sort key is named "sort_key" with type (N)
 *
 * <p>This example also requires using a KMS Key whose ARN is provided in CLI arguments. You need the
 * following access on this key:
 *   - GenerateDataKeyWithoutPlaintext
 *   - Decrypt
 */
public class SharedCacheAcrossHierarchicalKeyringsExample {

  public static void putAndGetItem(
    String tableName,
    String branchKeyId,
    String keyStoreTableName,
    String logicalKeyStoreName,
    String partitionId,
    String kmsKeyArn
  ) {
    // 1. Create the CryptographicMaterialsCache (CMC) to share across multiple Hierarchical Keyrings
    //    using the Material Providers Library
    //      This CMC takes in:
    //      - CacheType
    CryptographicMaterialsCache sharedCryptographicMaterialsCache =
      CryptographicMaterialsCache.create(CacheType.defaultCache(100));

    // 2. Create a CacheType object for the sharedCryptographicMaterialsCache. Note that the `cache`
    // parameter in the Hierarchical Keyring Input takes a `CacheType` as input.
    // This is the `Shared` CacheType that passes an already initialized shared cache.
    CacheType sharedCache = CacheType.shared(sharedCryptographicMaterialsCache);

    // Initial KeyStore Setup: This example requires that you have already
    // created your KeyStore, and have populated it with a new branch key.

    // 3. Configure your KeyStore resource keystore1.
    //    This SHOULD be the same configuration that you used
    //    to initially create and populate your KeyStore.
    // Note that keyStoreTableName is the physical Key Store,
    // and keystore1 is instances of this physical Key Store.
    // The DynamoDB and AWS KMS clients the keystore uses. Both are optional: without them, the
    // keystore creates its own in the region of the KMS key ARN. KmsClient.create() and
    // DynamoDbClient.create() use your environment's default region and credentials instead.
    // The try block closes them when it ends, so everything that uses the keystore stays inside it.
    try (
      DynamoDbClient keyStore1DynamoDbClient = DynamoDbClient.create();
      KmsClient keyStore1KmsClient = KmsClient.create()
    ) {
      BranchKeyStore keystore1 = BranchKeyStore
        .builder()
        .ddbTableName(keyStoreTableName)
        .logicalKeyStoreName(logicalKeyStoreName)
        .kmsConfiguration(KmsConfiguration.kmsKeyArn(kmsKeyArn))
        .ddbClient(keyStore1DynamoDbClient)
        .kmsClient(keyStore1KmsClient)
        .build();

      // 4. Create the Hierarchical Keyring HK1 with Key Store instance K1, partitionId,
      //    the shared Cache and the BranchKeyId.
      //    Unlike HierarchicalKeyringExample, where the keyring creates its own cache from a cache
      //    type, this passes in one already created cache that both keyrings share.

      // This example creates a Hierarchical Keyring for a single BranchKeyId. You can, however, use
      // an ItemBranchKeyIdSupplier as per your use-case. See HierarchicalKeyringExample.java for more
      // information.

      // Please make sure that you read the guidance on how to set Partition ID, Logical Key Store Name and
      // Branch Key ID at the top of this example before creating Hierarchical Keyrings with a Shared Cache.
      // partitionId for this example is a random UUID
      Keyring hierarchicalKeyring1 = AwsKmsHierarchicalKeyring
        .builder()
        .keyStore(keystore1)
        .branchKeyId(branchKeyId)
        // This dictates how often we call back to KMS to authorize use of the branch keys
        .ttl(Duration.ofSeconds(600))
        .cache(sharedCache)
        .partitionId(partitionId)
        .build();

      // 5. Decide how each attribute of your items is protected. BasicPutGetExample
      //    explains each action (encryptAndSign, signOnly, signAndIncludeInEncryptionContext,
      //    doNothing), and why the partition and sort keys get none.
      //    Every attribute you write must either have an action or start with the prefix set below;
      //    writing an item with any other attribute fails.
      //
      //    Then decide which attributes are left out of the signature. Two separate settings do this.
      //    They do different jobs, and you can use either one, both, or neither:
      //
      //    - doNothingPrefix(":") is a naming rule. Every attribute whose name starts with this text
      //      is treated as doNothing, without being listed anywhere. It lets you add new unsigned
      //      attributes later just by naming them with the prefix, with no configuration change. Pick
      //      the prefix before you write any items, and do not change it afterwards.
      //
      //    - doNothing("name", ...) lists specific attributes by name, for unsigned attributes whose
      //      names do not start with the prefix. Never remove a name from this list while items that
      //      have that attribute may still be in the table, or reading those items fails. To add a
      //      name, first update the configuration on every reader, and only then start writing the
      //      new attribute.
      //
      //    This example sets the prefix ":" so that unsigned attributes can be added later. The items
      //    it writes do not have any yet.

      // Build the schema from the choices above.
      ItemEncryptionSchema schema = ItemEncryptionSchema
        .builder()
        .partitionKeyName("partition_key")
        .sortKeyName("sort_key")
        .encryptAndSign("sensitive_data")
        .doNothingPrefix(":")
        .build();

      // 6. Get the DynamoDB Client for Hierarchical Keyring 1.
      try (
        DynamoDbClient dynamoDbClient1 = createDynamoDbClient(
          tableName,
          hierarchicalKeyring1,
          schema
        )
      ) {
        // 7. Encrypt Decrypt roundtrip with dynamoDbClient1
        putAndGetItemWithClient(tableName, dynamoDbClient1);

        // Through the above encrypt and decrypt roundtrip, the cache will be populated and
        // the cache entries can be used by another Hierarchical Keyring with the
        // - Same Partition ID
        // - Same Logical Key Store Name of the Key Store for the Hierarchical Keyring
        // - Same Branch Key ID

        // 8. Configure your KeyStore resource keystore2.
        //       This SHOULD be the same configuration that you used
        //       to initially create and populate your physical KeyStore.
        //    Note that keyStoreTableName is the physical Key Store,
        //    and keystore2 is instances of this physical Key Store.

        // Note that for this example, keystore2 is identical to keystore1.
        // You can optionally change configurations like KMS Client or KMS Key ID based
        // on your use-case.
        // Make sure you have the required permissions to use different configurations.

        // - If you want to share cache entries across two keyrings HK1 and HK2,
        //   you should set the Logical Key Store Names for both
        //   Key Store instances (K1 and K2) to be the same.
        // - If you set the Logical Key Store Names for K1 and K2 to be different,
        //   HK1 (which uses Key Store instance K1) and HK2 (which uses Key Store
        //   instance K2) will NOT be able to share cache entries.
        // The DynamoDB and AWS KMS clients the keystore uses. Both are optional: without them, the
        // keystore creates its own in the region of the KMS key ARN. KmsClient.create() and
        // DynamoDbClient.create() use your environment's default region and credentials instead.
        // The try block closes them when it ends, so everything that uses the keystore stays inside it.
        try (
          DynamoDbClient keyStore2DynamoDbClient = DynamoDbClient.create();
          KmsClient keyStore2KmsClient = KmsClient.create()
        ) {
          BranchKeyStore keystore2 = BranchKeyStore
            .builder()
            .ddbTableName(keyStoreTableName)
            .logicalKeyStoreName(logicalKeyStoreName)
            .kmsConfiguration(KmsConfiguration.kmsKeyArn(kmsKeyArn))
            .ddbClient(keyStore2DynamoDbClient)
            .kmsClient(keyStore2KmsClient)
            .build();

          // 9. Create the Hierarchical Keyring HK2 with Key Store instance K2, the shared Cache
          //    and the same partitionId and BranchKeyId used in HK1 because we want to share cache entries
          //    (and experience cache HITS).

          // Please make sure that you read the guidance on how to set Partition ID, Logical Key
          // Store Name and Branch Key ID at the top of this example before creating Hierarchical
          // Keyrings with a Shared Cache. partitionId for this example is a random UUID
          Keyring hierarchicalKeyring2 = AwsKmsHierarchicalKeyring
            .builder()
            .keyStore(keystore2)
            .branchKeyId(branchKeyId)
            // This dictates how often we call back to KMS to authorize use of the branch keys
            .ttl(Duration.ofSeconds(600))
            .cache(sharedCache)
            .partitionId(partitionId)
            .build();

          // 10. Get the DynamoDB Client for Hierarchical Keyring 2.
          try (
            DynamoDbClient dynamoDbClient2 = createDynamoDbClient(
              tableName,
              hierarchicalKeyring2,
              schema
            )
          ) {
            // 11. Encrypt Decrypt roundtrip with dynamoDbClient2
            putAndGetItemWithClient(tableName, dynamoDbClient2);
          }
        }
      }
    }
  }

  private static DynamoDbClient createDynamoDbClient(
    String tableName,
    Keyring hierarchicalKeyring,
    ItemEncryptionSchema schema
  ) {
    // Create the DynamoDB Encryption configuration for the table we will be writing to.
    DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .schema(schema)
      .keyring(hierarchicalKeyring)
      .build();

    // Create the DynamoDB Encryption Interceptor
    DynamoDbEncryptionInterceptor encryptionInterceptor =
      DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();

    // Create a new AWS SDK DynamoDB client using the DynamoDB Encryption Interceptor above
    DynamoDbClient dynamoDbClient = DynamoDbClient
      .builder()
      .overrideConfiguration(overrides ->
        overrides.addExecutionInterceptor(encryptionInterceptor)
      )
      .build();

    return dynamoDbClient;
  }

  private static void putAndGetItemWithClient(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Put an item into our table using the given DynamoDB client.
    // Before the item gets sent to DynamoDB, it will be encrypted
    // client-side, according to our configuration.
    Map<String, AttributeValue> item = Map.of(
      "partition_key",
      AttributeValue.fromS("id"),
      "sort_key",
      AttributeValue.fromN("0"),
      "sensitive_data",
      AttributeValue.fromS("encrypt and sign me!")
    );
    PutItemRequest putRequest = PutItemRequest
      .builder()
      .tableName(tableName)
      .item(item)
      .build();

    dynamoDbClient.putItem(putRequest);

    // Get the item back from our table using the same client.
    // The client will decrypt the item client-side, and return
    // back the original item.
    Map<String, AttributeValue> keyToGet = Map.of(
      "partition_key",
      AttributeValue.fromS("id"),
      "sort_key",
      AttributeValue.fromN("0")
    );
    GetItemRequest getRequest = GetItemRequest
      .builder()
      .key(keyToGet)
      .tableName(tableName)
      .build();

    GetItemResponse getResponse = dynamoDbClient.getItem(getRequest);

    // Demonstrate that GetItem succeeded and returned the decrypted item
    Map<String, AttributeValue> returnedItem = getResponse.item();
    assert returnedItem
      .get("sensitive_data")
      .s()
      .equals("encrypt and sign me!");
  }

  public static void main(String[] args) {
    if (args.length < 6) {
      throw new IllegalArgumentException(
        "To run this example, include the table name, branchKeyId, " +
        "keyStoreTableName, logicalKeyStoreName, partitionId, and kmsKeyArn in args"
      );
    }
    String tableName = args[0];
    String branchKeyId = args[1];
    String keyStoreTableName = args[2];
    String logicalKeyStoreName = args[3];
    String partitionId = args[4];
    String kmsKeyArn = args[5];
    putAndGetItem(
      tableName,
      branchKeyId,
      keyStoreTableName,
      logicalKeyStoreName,
      partitionId,
      kmsKeyArn
    );
  }
}
