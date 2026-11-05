package software.amazon.cryptography.dbesdk.examples.enhanced;

import java.util.List;
import software.amazon.awssdk.enhanced.dynamodb.Document;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.TransactGetItemsEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.TransactWriteItemsEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.enhancedclient.EnhancedClientSchemas;
import software.amazon.cryptography.dbesdk.examples.ExampleUtils;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkMultiKeyring;

/*
 This example sets up DynamoDB Encryption for the DynamoDB Enhanced Client and uses the high level
 transactWriteItems() and transactGetItems() APIs to demonstrate writing three client-side encrypted
 items, each modelled by a different annotated class, into a single DynamoDB table in one
 transaction, and then retrieving and decrypting those items from DynamoDB in one transaction.

 Running this example requires access to the DynamoDB Table whose name is provided in CLI arguments. This
 table must be configured with the following primary key configuration:
   - Partition key is named "partition_key" with type (S)
   - Sort key is named "sort_key" with type (N)
*/
public class SingleTableExample {

  public static void transactPutAndGetItems(String kmsKeyId, String tableName) {
    // 1. Create a Keyring. This Keyring will be responsible for protecting the data keys that
    //    protect your data. For this example, we will create a AWS KMS Keyring with the AWS KMS Key
    //    we want to use. We will use the AWS KMS MRK Multi Keyring, as it will correctly handle both
    //    single region and Multi-Region KMS Keys.
    final Keyring kmsKeyring = AwsKmsMrkMultiKeyring
      .builder()
      .generator(kmsKeyId)
      .build();

    // 2. Create a Table Schema over your annotated class (See SimpleClass.java in this directory).
    //    By default, all primary key attributes will be signed but not encrypted (SIGN_ONLY)
    //    and all non-primary key attributes will be encrypted and signed (ENCRYPT_AND_SIGN).
    //    If you want a particular non-primary key attribute to be signed but not encrypted,
    //    use the `DynamoDbEncryptionSignOnly` annotation.
    //    If you want a particular attribute to be neither signed nor encrypted (DO_NOTHING),
    //    use the `DynamoDbEncryptionDoNothing` annotation.
    final TableSchema<SimpleClass> tableSchema1 = TableSchema.fromBean(
      SimpleClass.class
    );
    final TableSchema<SimpleClass2> tableSchema2 = TableSchema.fromBean(
      SimpleClass2.class
    );
    final TableSchema<SimpleClass3> tableSchema3 = TableSchema.fromBean(
      SimpleClass3.class
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
    //    This example sets the prefix ":". Its item classes already mark ":attribute3" and
    //    ":attribute7" as doNothing; the prefix also lets you add more ":" attributes later without
    //    changing the class annotations.

    // Build the schema from the annotations and the prefix.
    final ItemEncryptionSchema schema = EnhancedClientSchemas
      .fromTableSchemas(tableSchema1, tableSchema2, tableSchema3)
      .doNothingPrefix(":")
      .build();

    // 4. Create the DynamoDB Encryption configuration for the table we will be writing to
    final DynamoDbTableEncryptionConfig tableConfig = DynamoDbTableEncryptionConfig
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
      .algorithmSuiteId(
        AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384
      )
      .build();

    // 5. Create the DynamoDB Encryption Interceptor
    final DynamoDbEncryptionInterceptor encryptionInterceptor =
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
      //    and create a Table with your modelled class
      final DynamoDbEnhancedClient enhancedClient = DynamoDbEnhancedClient
        .builder()
        .dynamoDbClient(dynamoDbClient)
        .build();
      final DynamoDbTable<SimpleClass> table1 = enhancedClient.table(
        tableName,
        tableSchema1
      );
      final DynamoDbTable<SimpleClass2> table2 = enhancedClient.table(
        tableName,
        tableSchema2
      );
      final DynamoDbTable<SimpleClass3> table3 = enhancedClient.table(
        tableName,
        tableSchema3
      );

      // 8. Put three items into your table in a single transaction using the
      //    DynamoDB Enhanced Client. The items will be encrypted client-side
      //    according to your configuration above before they are sent to DynamoDB.
      final SimpleClass item1 = new SimpleClass();
      item1.setPartitionKey(ExampleUtils.uniquePartitionKey("SingleTableExample1"));
      item1.setSortKey(0);
      item1.setAttribute1("item1 encrypt and sign me!");
      item1.setAttribute2("item1 sign me!");
      item1.setAttribute3("item1 ignore me!");

      final SimpleClass2 item2 = new SimpleClass2();
      item2.setPartitionKey(ExampleUtils.uniquePartitionKey("SingleTableExample2"));
      item2.setSortKey(0);
      item2.setAttribute4("item2 encrypt and sign me!");
      item2.setAttribute5("item2 sign me!");
      item2.setAttribute3("item2 ignore me!");

      final SimpleClass3 item3 = new SimpleClass3();
      item3.setPartitionKey(ExampleUtils.uniquePartitionKey("SingleTableExample3"));
      item3.setSortKey(0);
      item3.setAttribute6("item3 encrypt and sign me!");
      item3.setAttribute2("item3 sign me!");
      item3.setAttribute7("item3 sign and include me!");

      // Create enhanced request providing the table schema and the item types we want to write
      final TransactWriteItemsEnhancedRequest request =
        TransactWriteItemsEnhancedRequest
          .builder()
          .addPutItem(table1, item1)
          .addPutItem(table2, item2)
          .addPutItem(table3, item3)
          .build();
      enhancedClient.transactWriteItems(request);

      // 9. Get the three items back from the table in a single transaction using
      //    the DynamoDB Enhanced Client. The items will be decrypted client-side,
      //    and you will get back the original items.
      final SimpleClass key1 = new SimpleClass();
      key1.setPartitionKey(ExampleUtils.uniquePartitionKey("SingleTableExample1"));
      key1.setSortKey(0);

      final SimpleClass2 key2 = new SimpleClass2();
      key2.setPartitionKey(ExampleUtils.uniquePartitionKey("SingleTableExample2"));
      key2.setSortKey(0);

      final SimpleClass3 key3 = new SimpleClass3();
      key3.setPartitionKey(ExampleUtils.uniquePartitionKey("SingleTableExample3"));
      key3.setSortKey(0);

      final TransactGetItemsEnhancedRequest getRequest =
        TransactGetItemsEnhancedRequest
          .builder()
          .addGetItem(table1, key1)
          .addGetItem(table2, key2)
          .addGetItem(table3, key3)
          .build();
      final List<Document> getResult = enhancedClient.transactGetItems(
        getRequest
      );

      final SimpleClass result1 = getResult.get(0).getItem(table1);
      final SimpleClass2 result2 = getResult.get(1).getItem(table2);
      final SimpleClass3 result3 = getResult.get(2).getItem(table3);

      // Demonstrate we get the original items back
      assert "item1 encrypt and sign me!".equals(result1.getAttribute1());
      assert "item2 encrypt and sign me!".equals(result2.getAttribute4());
      assert "item3 encrypt and sign me!".equals(result3.getAttribute6());
    }
  }

  public static void main(final String[] args) {
    if (args.length < 2) {
      throw new IllegalArgumentException(
        "To run this example, include the kmsKeyId as args[0] and tableName as args[1]"
      );
    }
    final String kmsKeyId = args[0];
    final String tableName = args[1];
    transactPutAndGetItems(kmsKeyId, tableName);
  }
}
