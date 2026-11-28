package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.enhanced;

import static software.amazon.awssdk.enhanced.dynamodb.mapper.StaticAttributeTags.primaryPartitionKey;
import static software.amazon.awssdk.enhanced.dynamodb.mapper.StaticAttributeTags.primarySortKey;
import static software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.ManipulationUtils.assertManipulationProof;
import static software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.ManipulationUtils.assertNotManipulationProof;
import static software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.ManipulationUtils.assertProtectedByEncryptionContext;
import static software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.ManipulationUtils.manipulateByteAttribute;
import static software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.ManipulationUtils.manipulateNumberAttribute;
import static software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.ManipulationUtils.manipulateStringAttribute;

import java.util.Map;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.enhancedclient.DoNothingTag;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.enhancedclient.EnhancedClientSchemas;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.enhancedclient.SignOnlyTag;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.ExampleUtils;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.itemencryptor.DynamoDbItemEncryptor;
import software.amazon.cryptography.materialproviders.DbeAlgorithmSuite;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkMultiKeyring;

/**
 * This example sets up DynamoDB Encryption for the DynamoDB Enhanced Client using a Table Schema
 * built manually with the Table Schema Builder, rather than from an annotated class. It uses the
 * high level putItem() and getItem() APIs to demonstrate putting a client-side encrypted item into
 * DynamoDB and then retrieving and decrypting that item from DynamoDB. It then reads the item
 * without the encryption interceptor to show that it is stored encrypted and signed.
 *
 * <p>Running this example requires access to the DynamoDB Table whose name is provided in CLI arguments. This
 * table must be configured with the following primary key configuration:
 *   - Partition key is named "partition_key" with type (S)
 *   - Sort key is named "sort_key" with type (N)
 */
public class TableSchemaBuilderPutGetExample {

  public static void putAndGetItem(String kmsKeyId, String tableName) {
    // 1. Create a Keyring. This Keyring will be responsible for protecting the data keys that
    //    protect your data. For this example, we will create a AWS KMS Keyring with the AWS KMS Key
    //    we want to use. We will use the AWS KMS MRK Multi Keyring, as it will correctly handle both
    //    single region and Multi-Region KMS Keys.
    Keyring kmsKeyring = AwsKmsMrkMultiKeyring
      .builder()
      .generator(kmsKeyId)
      .build();

    // 2. Create a Table Schema Manually via the Table Schema Builder.
    //    By default, all primary key attributes will be signed but not encrypted (SIGN_ONLY)
    //    and all non-primary key attributes will be encrypted and signed (ENCRYPT_AND_SIGN).
    //    If you want a particular non-primary key attribute to be signed but not encrypted,
    //    use the `SignOnlyTag`.
    //    If you want a particular attribute to be neither signed nor encrypted (DO_NOTHING),
    //    use the `DoNothingTag`.
    TableSchema<SimpleItem> tableSchema = TableSchema
      .builder(SimpleItem.class)
      .newItemSupplier(SimpleItem::new)
      .addAttribute(
        String.class,
        attribute ->
          attribute
            .name("partition_key")
            .getter(SimpleItem::getPartitionKey)
            .setter(SimpleItem::setPartitionKey)
            .tags(primaryPartitionKey())
      )
      .addAttribute(
        int.class,
        attribute ->
          attribute
            .name("sort_key")
            .getter(SimpleItem::getSortKey)
            .setter(SimpleItem::setSortKey)
            .tags(primarySortKey())
      )
      .addAttribute(
        String.class,
        attribute ->
          attribute
            .name("attribute1")
            .getter(SimpleItem::getAttribute1)
            .setter(SimpleItem::setAttribute1)
      )
      .addAttribute(
        String.class,
        attribute ->
          attribute
            .name("attribute2")
            .getter(SimpleItem::getAttribute2)
            .setter(SimpleItem::setAttribute2)
            .tags(new SignOnlyTag())
      )
      .addAttribute(
        String.class,
        attribute ->
          attribute
            .name(":attribute3")
            .getter(SimpleItem::getAttribute3)
            .setter(SimpleItem::setAttribute3)
            .tags(new DoNothingTag())
      )
      .build();

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
    //    This example sets the prefix ":". Its table schema already tags ":attribute3" as
    //    doNothing; the prefix also lets you add more ":" attributes later without changing the
    //    schema.

    // Build the schema from the annotations and the prefix.
    ItemEncryptionSchema schema = EnhancedClientSchemas
      .fromTableSchemas(tableSchema)
      .doNothingPrefix(":")
      .build();

    // 4. Create the DynamoDB Encryption configuration for the table we will be writing to
    DynamoDbTableEncryptionConfig tableConfig = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
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
        DbeAlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384
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
      DynamoDbTable<SimpleItem> table = enhancedClient.table(
        tableName,
        tableSchema
      );

      // 8. Put an item into your table using the DynamoDB Enhanced Client.
      //    The item will be encrypted client-side according to your
      //    configuration above before it is sent to DynamoDB.
      SimpleItem item = new SimpleItem();
      item.setPartitionKey(
        ExampleUtils.uniquePartitionKey("TableSchemaBuilderPutGetExample")
      );
      item.setSortKey(0);
      item.setAttribute1("encrypt and sign me!");
      item.setAttribute2("sign me!");
      item.setAttribute3("ignore me!");
      table.putItem(item);

      // 9. Get the item back from the table using the DynamoDB Enhanced Client.
      //    The item will be decrypted client-side, and you will get back the
      //    original item.
      Key key = Key
        .builder()
        .partitionValue(
          ExampleUtils.uniquePartitionKey("TableSchemaBuilderPutGetExample")
        )
        .sortValue(0)
        .build();
      SimpleItem decrypted = table.getItem(requestBuilder ->
        requestBuilder.key(key)
      );
      // Demonstrate we get the original item back
      assert "encrypt and sign me!".equals(decrypted.getAttribute1());

      // Demonstrate, without the Enhanced Client, the record is encrypted
      try (
        DynamoDbClient plainDynamoDbClient = DynamoDbClient.builder().build()
      ) {
        GetItemResponse response =
          plainDynamoDbClient.getItem(requestBuilder -> {
            requestBuilder.key(key.primaryKeyMap(tableSchema));
            requestBuilder.tableName(tableName);
          });
        Map<String, AttributeValue> encryptedItem = response.item();
        // Assert the Encrypted Field is in Bytes
        assert encryptedItem.get("attribute1").b() != null;
        // Assert the Encrypted Field is not a String
        assert encryptedItem.get("attribute1").s() == null;
        // Assert the Signed Only Field is a String and is Equal to the input
        assert encryptedItem.get("attribute2").s() != null;
        assert encryptedItem.get("attribute2").s().equals(item.getAttribute2());
        // Assert the Not Signed, Not Encrypted Field is a String and is Equal to the input
        assert encryptedItem.get(":attribute3").s() != null;
        assert encryptedItem
          .get(":attribute3")
          .s()
          .equals(item.getAttribute3());

        // Verify the Signed Items are protected. The interceptor holds one item encryptor per table,
        // built from that table's configuration. itemEncryptor(tableName) returns that same
        // encryptor, so it decrypts with exactly the settings the interceptor used to write.
        DynamoDbItemEncryptor itemEncryptor =
          encryptionInterceptor.itemEncryptor(tableName);
        assertProtectedByEncryptionContext(
          itemEncryptor,
          manipulateStringAttribute(encryptedItem, "partition_key"),
          "partition_key"
        );
        assertProtectedByEncryptionContext(
          itemEncryptor,
          manipulateNumberAttribute(encryptedItem, "sort_key"),
          "sort_key"
        );
        assertManipulationProof(
          itemEncryptor,
          manipulateByteAttribute(encryptedItem, "attribute1"),
          "attribute1"
        );
        assertManipulationProof(
          itemEncryptor,
          manipulateStringAttribute(encryptedItem, "attribute2"),
          "attribute2"
        );
        assertNotManipulationProof(
          itemEncryptor,
          manipulateStringAttribute(encryptedItem, ":attribute3"),
          ":attribute3"
        );
      }
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
