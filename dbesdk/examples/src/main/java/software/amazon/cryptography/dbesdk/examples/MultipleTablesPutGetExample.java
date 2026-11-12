package software.amazon.cryptography.dbesdk.examples;

import java.util.List;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.Get;
import software.amazon.awssdk.services.dynamodb.model.ItemResponse;
import software.amazon.awssdk.services.dynamodb.model.Put;
import software.amazon.awssdk.services.dynamodb.model.TransactGetItem;
import software.amazon.awssdk.services.dynamodb.model.TransactGetItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkMultiKeyring;

/**
 * This example sets up one DynamoDB client that encrypts and decrypts items for two tables. Each
 * table has its own encryption configuration, and both configurations are given to one DynamoDB
 * Encryption Interceptor. The example then writes one item to each table in a single
 * TransactWriteItems call, and reads both back in a single TransactGetItems call. A call that
 * touches several tables, like these two, needs one client that knows the configuration of every
 * table in the call.
 *
 * <p>Running this example requires access to the two DynamoDB tables whose names are provided in CLI
 * arguments.
 * The customers table must have this primary key:
 *   - Partition key is named "customer_id" with type (S)
 * The orders table must have this primary key:
 *   - Partition key is named "customer_id" with type (S)
 *   - Sort key is named "order_id" with type (S)
 */
public class MultipleTablesPutGetExample {

  public static void putAndGetItems(
    String kmsKeyId,
    String customersTableName,
    String ordersTableName
  ) {
    // 1. Create a keyring. Both tables use the same keyring in this example. Each table
    //    configuration takes its own keyring, so you can also give each table a different one.
    Keyring kmsKeyring = AwsKmsMrkMultiKeyring
      .builder()
      .generator(kmsKeyId)
      .build();

    // 2. Decide how each attribute is protected, separately for each table. See
    //    BasicPutGetExample for what each action does. In short: encryptAndSign encrypts the value
    //    and detects any change to it; signOnly stores the value as plain text but detects any
    //    change to it. The partition key and the sort key get no action: the library always signs
    //    them and never encrypts them.
    ItemEncryptionSchema customersSchema = ItemEncryptionSchema
      .builder()
      .partitionKeyName("customer_id")
      .encryptAndSign("email", "shipping_address")
      .signOnly("customer_since")
      .build();
    ItemEncryptionSchema ordersSchema = ItemEncryptionSchema
      .builder()
      .partitionKeyName("customer_id")
      .sortKeyName("order_id")
      .encryptAndSign("card_last4")
      .signOnly("order_total")
      .build();

    // 3. Create one encryption configuration per table. tableName is the table's name in
    //    DynamoDB, which is how the interceptor finds the configuration for each request.
    //    logicalTableName is the name bound into each item's encryption, so an item can only be
    //    decrypted with a configuration that uses the same logical table name. Each table needs
    //    a different logicalTableName.
    DynamoDbTableEncryptionConfig customersConfig =
      DynamoDbTableEncryptionConfig
        .builder()
        .tableName(customersTableName)
        .logicalTableName(customersTableName)
        .schema(customersSchema)
        .keyring(kmsKeyring)
        .build();
    DynamoDbTableEncryptionConfig ordersConfig = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(ordersTableName)
      .logicalTableName(ordersTableName)
      .schema(ordersSchema)
      .keyring(kmsKeyring)
      .build();

    // 4. Give both configurations to one DynamoDB Encryption Interceptor. Building it fails if two
    //    configurations have the same tableName or the same logicalTableName.
    DynamoDbEncryptionInterceptor encryptionInterceptor =
      DynamoDbEncryptionInterceptor
        .builder()
        .tableConfigs(customersConfig, ordersConfig)
        .build();

    // 5. Create a DynamoDB client that uses the interceptor.
    try (
      DynamoDbClient dynamoDbClient = DynamoDbClient
        .builder()
        .overrideConfiguration(overrides ->
          overrides.addExecutionInterceptor(encryptionInterceptor)
        )
        .build()
    ) {
      // 6. Write one item to each table in one transaction. The client encrypts each item with
      //    the configuration of the table it is written to.
      String customerId = ExampleUtils.uniquePartitionKey("customer1");
      Map<String, AttributeValue> customer = Map.of(
        "customer_id",
        AttributeValue.fromS(customerId),
        "email",
        AttributeValue.fromS("customer1@example.com"),
        "shipping_address",
        AttributeValue.fromS("123 Any Street, Anytown"),
        "customer_since",
        AttributeValue.fromS("2024-01-15")
      );
      Map<String, AttributeValue> order = Map.of(
        "customer_id",
        AttributeValue.fromS(customerId),
        "order_id",
        AttributeValue.fromS("order-0001"),
        "card_last4",
        AttributeValue.fromS("4321"),
        "order_total",
        AttributeValue.fromN("42.50")
      );
      TransactWriteItemsRequest writeRequest = TransactWriteItemsRequest
        .builder()
        .transactItems(
          TransactWriteItem
            .builder()
            .put(
              Put.builder().tableName(customersTableName).item(customer).build()
            )
            .build(),
          TransactWriteItem
            .builder()
            .put(Put.builder().tableName(ordersTableName).item(order).build())
            .build()
        )
        .build();

      dynamoDbClient.transactWriteItems(writeRequest);

      // 7. Read both items back in one transaction. The client decrypts each returned item with
      //    the configuration of the table it came from. TransactGetItems reads the latest
      //    committed version of each item, so both items written above are returned.
      TransactGetItemsRequest getRequest = TransactGetItemsRequest
        .builder()
        .transactItems(
          TransactGetItem
            .builder()
            .get(
              Get
                .builder()
                .tableName(customersTableName)
                .key(Map.of("customer_id", AttributeValue.fromS(customerId)))
                .build()
            )
            .build(),
          TransactGetItem
            .builder()
            .get(
              Get
                .builder()
                .tableName(ordersTableName)
                .key(
                  Map.of(
                    "customer_id",
                    AttributeValue.fromS(customerId),
                    "order_id",
                    AttributeValue.fromS("order-0001")
                  )
                )
                .build()
            )
            .build()
        )
        .build();

      // The responses come back in the same order as the requests above.
      List<ItemResponse> responses = dynamoDbClient
        .transactGetItems(getRequest)
        .responses();

      // Demonstrate that both items were decrypted with their own table's configuration
      Map<String, AttributeValue> returnedCustomer = responses.get(0).item();
      assert returnedCustomer.get("email").s().equals("customer1@example.com");
      Map<String, AttributeValue> returnedOrder = responses.get(1).item();
      assert returnedOrder.get("card_last4").s().equals("4321");
    }
  }

  public static void main(String[] args) {
    if (args.length < 3) {
      throw new IllegalArgumentException(
        "To run this example, include the kmsKeyId as args[0], customersTableName as args[1], " +
        "and ordersTableName as args[2]"
      );
    }
    String kmsKeyId = args[0];
    String customersTableName = args[1];
    String ordersTableName = args[2];
    putAndGetItems(kmsKeyId, customersTableName, ordersTableName);
  }
}
