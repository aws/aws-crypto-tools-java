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
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;

/**
 * This example sets up DynamoDB Encryption for the AWS SDK client using the Hierarchical Keyring,
 * which establishes a key hierarchy where "branch" keys are persisted in DynamoDB. These branch keys
 * are used to protect your data keys, and these branch keys are themselves protected by a root KMS
 * Key.
 *
 * <p>Establishing a key hierarchy like this has two benefits:
 *
 * <p>First, by caching the branch key material, and only calling back to KMS to re-establish
 * authentication regularly according to your configured TTL, you limit how often you need to call
 * back to KMS to protect your data. This is a performance/security tradeoff, where your
 * authentication, audit, and logging from KMS is no longer one-to-one with every encrypt or decrypt
 * call. However, the benefit is that you no longer have to make a network call to KMS for every
 * encrypt or decrypt.
 *
 * <p>Second, this key hierarchy makes it easy to hold multi-tenant data that is isolated per branch key
 * in a single DynamoDB table. You can create a branch key for each tenant in your table, and encrypt
 * all that tenant's data under that distinct branch key. On decrypt, you can either statically
 * configure a single branch key to ensure you are restricting decryption to a single tenant, or you
 * can implement an interface that lets you map the primary key on your items to the branch key that
 * should be responsible for decrypting that data.
 *
 * <p>This example then demonstrates configuring a Hierarchical Keyring with a Branch Key ID Supplier to
 * encrypt and decrypt data for two separate tenants.
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
public class HierarchicalKeyringExample {

  public static void putAndGetItem(
    String tableName,
    String tenant1BranchKeyId,
    String tenant2BranchKeyId,
    String keyStoreTableName,
    String logicalKeyStoreName,
    String kmsKeyArn
  ) {
    // Initial KeyStore Setup: This example requires that you have already
    // created your KeyStore, and have populated it with two new branch keys.
    // See the "Create KeyStore Table Example" and "Create KeyStore Key Example"
    // for an example of how to do this.

    // 1. Configure your KeyStore resource.
    //    This SHOULD be the same configuration that you used
    //    to initially create and populate your KeyStore.
    // The DynamoDB and AWS KMS clients the keystore uses. Both are optional: without them, the
    // keystore creates its own in the region of the KMS key ARN. KmsClient.create() and
    // DynamoDbClient.create() use your environment's default region and credentials instead.
    // The try block closes them when it ends, so everything that uses the keystore stays inside it.
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

      // 2. Create a Branch Key ID Supplier. ExampleBranchKeyIdSupplier (in this directory) picks a
      //    branch key ID from the item's attributes. It implements ItemBranchKeyIdSupplier, which
      //    the hierarchical keyring accepts directly: the library turns the encryption context the
      //    keyring receives back into the item's attributes before calling the example supplier.
      ExampleBranchKeyIdSupplier branchKeyIdSupplier =
        new ExampleBranchKeyIdSupplier(tenant1BranchKeyId, tenant2BranchKeyId);

      // 3. Create the Hierarchical Keyring, using the Branch Key ID Supplier above.
      //    With this configuration, the AWS SDK Client ultimately configured will be capable
      //    of encrypting or decrypting items for either tenant (assuming correct KMS access).
      //    If you want to restrict the client to only encrypt or decrypt for a single tenant,
      //    configure this Hierarchical Keyring using `.branchKeyId(tenant1BranchKeyId)` instead
      //    of `.branchKeyIdSupplier(branchKeyIdSupplier)`.
      Keyring hierarchicalKeyring = AwsKmsHierarchicalKeyring
        .builder()
        .keyStore(keyStore)
        .branchKeyIdSupplier(branchKeyIdSupplier)
        .ttl(Duration.ofSeconds(600)) // This dictates how often we call back to KMS to authorize use of the branch keys
        .cache(CacheType.defaultCache(100)) // This dictates how many branch keys will be held locally
        .build();

      // 4. Decide how each attribute of your items is protected. BasicPutGetExample
      //    explains each action (encryptAndSign, signOnly, signAndIncludeInEncryptionContext,
      //    doNothing), and why the partition and sort keys get none.
      //    Every attribute you write must either have an action or start with the prefix set in the
      //    next step; writing an item with any other attribute fails.

      // 5. Decide which attributes are left out of the signature. Two separate settings do this. They
      //    do different jobs, and you can use either one, both, or neither:
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
        .encryptAndSign("tenant_sensitive_data")
        .doNothingPrefix(":")
        .build();

      // 6. Create the DynamoDB Encryption configuration for the table we will be writing to.
      DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
        .builder()
        .tableName(tableName)
        .schema(schema)
        .keyring(hierarchicalKeyring)
        .build();

      // 7. Create the DynamoDB Encryption Interceptor
      DynamoDbEncryptionInterceptor encryptionInterceptor =
        DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();

      // 8. Create a new AWS SDK DynamoDB client using the DynamoDB Encryption Interceptor above
      try (
        DynamoDbClient dynamoDbClient = DynamoDbClient
          .builder()
          .overrideConfiguration(overrides ->
            overrides.addExecutionInterceptor(encryptionInterceptor)
          )
          .build()
      ) {
        // 9. Put an item into our table using the above client.
        //    Before the item gets sent to DynamoDB, it will be encrypted
        //    client-side, according to our configuration.
        //    Because the item we are writing uses "tenant1Id" as our partition value,
        //    based on the code we wrote in the ExampleBranchKeyIdSupplier,
        //    `tenant1BranchKeyId` will be used to encrypt this item.
        Map<String, AttributeValue> item = Map.of(
          "partition_key",
          AttributeValue.fromS("tenant1Id"),
          "sort_key",
          AttributeValue.fromN("0"),
          "tenant_sensitive_data",
          AttributeValue.fromS("encrypt and sign me!")
        );
        PutItemRequest putRequest = PutItemRequest
          .builder()
          .tableName(tableName)
          .item(item)
          .build();

        dynamoDbClient.putItem(putRequest);

        // 10. Get the item back from our table using the same client.
        //     The client will decrypt the item client-side, and return
        //     back the original item.
        //     Because the returned item's partition value is "tenant1Id",
        //     based on the code we wrote in the ExampleBranchKeyIdSupplier,
        //     `tenant1BranchKeyId` will be used to decrypt this item.
        Map<String, AttributeValue> keyToGet = Map.of(
          "partition_key",
          AttributeValue.fromS("tenant1Id"),
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
          .get("tenant_sensitive_data")
          .s()
          .equals("encrypt and sign me!");
      }
    }
  }

  public static void main(String[] args) {
    if (args.length < 6) {
      throw new IllegalArgumentException(
        "To run this example, include the table name, tenant1BranchKeyId, " +
        "tenant2BranchKeyId, keyStoreTableName, logicalKeyStoreName, and kmsKeyArn in args"
      );
    }
    String tableName = args[0];
    String tenant1BranchKeyId = args[1];
    String tenant2BranchKeyId = args[2];
    String keyStoreTableName = args[3];
    String logicalKeyStoreName = args[4];
    String kmsKeyArn = args[5];
    putAndGetItem(
      tableName,
      tenant1BranchKeyId,
      tenant2BranchKeyId,
      keyStoreTableName,
      logicalKeyStoreName,
      kmsKeyArn
    );
  }
}
