package software.amazon.cryptography.dbesdk.examples.enhanced;

import java.util.List;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.PageIterable;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.enhancedclient.EnhancedClientSchemas;
import software.amazon.cryptography.dbesdk.examples.ExampleUtils;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkMultiKeyring;

/**
 * This example sets up DynamoDB Encryption for the DynamoDB Enhanced Client and uses the high level
 * putItem() and getItem() APIs to demonstrate putting a client-side encrypted item into DynamoDB and
 * then retrieving and decrypting that item from DynamoDB.
 *
 * <p>Running this example requires access to the DynamoDB Table whose name is provided in CLI arguments. This
 * table must be configured with the following primary key configuration:
 *   - Partition key is named "partition_key" with type (S)
 *   - Sort key is named "sort_key" with type (N)
 */
public class EnhancedPutGetExample {

  public static void putAndGetItem(String kmsKeyId, String tableName) {
    // 1. Create a Keyring. This Keyring will be responsible for protecting the data keys that
    //    protect your data. For this example, we will create a AWS KMS Keyring with the AWS KMS Key
    //    we want to use. We will use the AWS KMS MRK Multi Keyring, as it will correctly handle both
    //    single region and Multi-Region KMS Keys.
    Keyring kmsKeyring = AwsKmsMrkMultiKeyring
      .builder()
      .generator(kmsKeyId)
      .build();

    // 2. Create a Table Schema over your annotated class (See SimpleEncryptionContextItem.java in
    //    this directory).
    //    By default, all primary key attributes will be signed but not encrypted (SIGN_ONLY)
    //    and all non-primary key attributes will be encrypted and signed (ENCRYPT_AND_SIGN).
    //    If you want a particular non-primary key attribute to be signed but not encrypted,
    //    use the `DynamoDbEncryptionSignOnly` annotation.
    //    If you want a particular attribute to be neither signed nor encrypted (DO_NOTHING),
    //    use the `DynamoDbEncryptionDoNothing` annotation.
    TableSchema<SimpleEncryptionContextItem> tableSchema = TableSchema.fromBean(
      SimpleEncryptionContextItem.class
    );

    // 3. Decide which attributes are left out of the signature. In your item classes, an attribute
    //    marked as doNothing (with the DynamoDbEncryptionDoNothing annotation or the DoNothingTag)
    //    is already left out. On top of that, you can set a prefix:
    //
    //    - doNothingPrefix(":") is a naming rule. Every attribute whose name starts with this text
    //      is treated as doNothing. It lets you add new unsigned attributes later just by naming
    //      them with the prefix. Pick the prefix before you write any items, and do not change it
    //      afterwards.
    //
    //    Never remove the doNothing marking from an attribute while items that have that attribute
    //    may still be in the table, or reading those items fails. To mark a new attribute as
    //    doNothing, first update every reader, and only then start writing the new attribute.
    //
    //    This example sets the prefix ":". Its item class already marks ":attribute3" as doNothing;
    //    the prefix also lets you add more ":" attributes later without changing the class
    //    annotations.

    // Build the schema from the annotations and the prefix. SimpleEncryptionContextItem marks attribute4 with
    // @DynamoDbEncryptionSignAndIncludeInEncryptionContext, so this schema must also include the
    // primary key in the encryption context.
    ItemEncryptionSchema schema = EnhancedClientSchemas
      .fromTableSchemas(tableSchema)
      .signAndIncludePrimaryKeysInEncryptionContext(true)
      .doNothingPrefix(":")
      .build();

    // 4. Create the DynamoDB Encryption configuration for the table we will be writing to
    DynamoDbTableEncryptionConfig tableConfig = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .logicalTableName(tableName)
      .schema(schema)
      .keyring(kmsKeyring)
      // Specifying an algorithm suite is not required,
      // but is done here to demonstrate how to do so.
      // We suggest using the
      // `ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384` suite,
      // which includes AES-GCM with key derivation, signing, and key commitment.
      // This is also the default algorithm suite if one is not specified in this config.
      // For more information on supported algorithm suites, see:
      //   https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/supported-algorithms.html
      .algorithmSuite(
        AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384
      )
      .build();

    // 5. Create the DynamoDB Encryption Interceptor
    DynamoDbEncryptionInterceptor encryptionInterceptor =
      DynamoDbEncryptionInterceptor.builder().tableConfigs(tableConfig).build();

    // 6. Create a new AWS SDK DynamoDB client using the DynamoDB Encryption Interceptor above
    try (
      DynamoDbClient dynamoDbClient = DynamoDbClient
        .builder()
        .overrideConfiguration(overrides ->
          overrides.addExecutionInterceptor(encryptionInterceptor)
        )
        .build()
    ) {
      // 7. Create the DynamoDbEnhancedClient using the AWS SDK Client created above,
      //    and create a Table with your modeled class
      DynamoDbEnhancedClient enhancedClient = DynamoDbEnhancedClient
        .builder()
        .dynamoDbClient(dynamoDbClient)
        .build();
      DynamoDbTable<SimpleEncryptionContextItem> table = enhancedClient.table(
        tableName,
        tableSchema
      );

      // 8. Put an item into your table using the DynamoDB Enhanced Client.
      //    The item will be encrypted client-side according to your
      //    configuration above before it is sent to DynamoDB.
      SimpleEncryptionContextItem item = new SimpleEncryptionContextItem();
      item.setPartitionKey(
        ExampleUtils.uniquePartitionKey("EnhancedPutGetExample")
      );
      item.setSortKey(0);
      item.setAttribute1("encrypt and sign me!");
      item.setAttribute2("sign me!");
      item.setAttribute3("ignore me!");
      item.setAttribute4("sign and include me!");

      table.putItem(item);

      // 9. Get the item back from the table using the DynamoDB Enhanced Client.
      //    The item will be decrypted client-side, and you will get back the
      //    original item.
      Key key = Key
        .builder()
        .partitionValue(
          ExampleUtils.uniquePartitionKey("EnhancedPutGetExample")
        )
        .sortValue(0)
        .build();

      SimpleEncryptionContextItem result = table.getItem(requestBuilder ->
        requestBuilder.key(key)
      );

      // Demonstrate we get the original item back
      assert "encrypt and sign me!".equals(result.getAttribute1());

      // retrieve the same record via a Query
      PageIterable<SimpleEncryptionContextItem> items = table.query(
        QueryConditional.keyEqualTo(keyBuilder ->
          keyBuilder.partitionValue(
            ExampleUtils.uniquePartitionKey("EnhancedPutGetExample")
          )
        )
      );
      List<SimpleEncryptionContextItem> itemList = items
        .items()
        .stream()
        .toList();
      assert itemList.size() == 1;
      assert "encrypt and sign me!".equals(itemList.get(0).getAttribute1());
    }
  }

  public static void main(String[] args) {
    if (args.length < 2) {
      throw new IllegalArgumentException(
        "To run this example, include the kmsKeyId as args[0] and tableName as args[1]"
      );
    }
    String kmsKeyId = args[0];
    String tableName = args[1];
    putAndGetItem(kmsKeyId, tableName);
  }
}
