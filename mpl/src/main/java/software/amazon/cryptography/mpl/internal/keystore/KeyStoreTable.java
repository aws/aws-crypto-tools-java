// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal.keystore;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import software.amazon.awssdk.services.dynamodb.model.TableDescription;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;
import software.amazon.cryptography.mpl.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.mpl.exceptions.ResourceNotFoundException;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.AwsErrors;

/** The key store's DynamoDB calls, per CreateKeyStoreTable.dfy and DDBKeystoreOperations.dfy. */
final class KeyStoreTable {

  private static final List<AttributeDefinition> ATTRIBUTE_DEFINITIONS = Arrays.asList(
    AttributeDefinition.builder()
      .attributeName(KeyStoreItems.BRANCH_KEY_IDENTIFIER_FIELD)
      .attributeType(ScalarAttributeType.S)
      .build(),
    AttributeDefinition.builder().attributeName(KeyStoreItems.TYPE_FIELD).attributeType(ScalarAttributeType.S).build()
  );
  //= spec/framework/branch-key-store.md#keyschema
  //# The following KeySchema MUST be configured on the table:
  private static final List<KeySchemaElement> KEY_SCHEMA = Arrays.asList(
    KeySchemaElement.builder().attributeName(KeyStoreItems.BRANCH_KEY_IDENTIFIER_FIELD).keyType(KeyType.HASH).build(),
    KeySchemaElement.builder().attributeName(KeyStoreItems.TYPE_FIELD).keyType(KeyType.RANGE).build()
  );
  // DynamoDB TableArn: 1 to 1024 characters.
  private static final int MAX_TABLE_ARN_LENGTH = 1024;

  private static final String BRANCH_KEY_PLACEHOLDER = "#BranchKeyIdentifierField";
  private static final Map<String, String> BRANCH_KEY_PLACEHOLDER_NAMES = Collections.singletonMap(
    BRANCH_KEY_PLACEHOLDER,
    KeyStoreItems.BRANCH_KEY_IDENTIFIER_FIELD
  );
  private static final String BRANCH_KEY_NOT_EXIST = "attribute_not_exists(" + BRANCH_KEY_PLACEHOLDER + ")";
  private static final String BRANCH_KEY_EXISTS = "attribute_exists(" + BRANCH_KEY_PLACEHOLDER + ")";

  private final String tableName;
  private final DynamoDbClient ddb;

  KeyStoreTable(String tableName, DynamoDbClient ddb) {
    this.tableName = tableName;
    this.ddb = ddb;
  }

  /** Creates the table unless it exists; returns the ARN of the table, which must have the key store's key schema. */
  String createIfMissing() {
    TableDescription table;
    try {
      //= spec/framework/branch-key-store.md#createkeystore
      //# This operation MUST first calls the DDB::DescribeTable API with the configured `tableName`.
      table = ddb.describeTable(r -> r.tableName(tableName)).table();
    //= spec/framework/branch-key-store.md#createkeystore
    //# If the client responds with a `ResourceNotFoundException`,
    //# then this operation MUST continue and
    } catch (software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException missing) {
      try {
        //= spec/framework/branch-key-store.md#createkeystore
        //# MUST call [AWS DDB CreateTable](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html)
        //# with the following specifics:

        //= spec/framework/branch-key-store.md#createkeystore
        //= type=implication
        //# - TableName is the configured tableName.
        //# - [KeySchema](#keyschema) as defined below.
        table =
          ddb
            .createTable(r ->
              r
                .attributeDefinitions(ATTRIBUTE_DEFINITIONS)
                .tableName(tableName)
                .keySchema(KEY_SCHEMA)
                .billingMode(BillingMode.PAY_PER_REQUEST)
            )
            .tableDescription();
      //= spec/framework/branch-key-store.md#createkeystore
      //# If the operation fails to create table, the operation MUST fail.
      } catch (SdkException e) {
        throw AwsErrors.from(e);
      }
    } catch (SdkException e) {
      throw AwsErrors.from(e);
    }
    //= spec/framework/branch-key-store.md#createkeystore
    //# If the response is successful, this operation validates that the table has the expected
    //# [KeySchema](#keyschema) as defined below.
    //# If the [KeySchema](#keyschema) does not match
    //# this operation MUST yield an error.
    if (table == null || !hasKeyStoreSchema(table)) {
      throw new ValidationException(KeyStoreMessages.TABLE_NOT_KEY_STORE);
    }
    //= spec/framework/branch-key-store.md#createkeystore
    //# If the operation successfully creates a table, the operation MUST return the AWS DDB Table Arn
    //# back to the caller.
    return table.tableArn();
  }

  // The table may define more attributes and keys, such as indexes, as long as it has these.
  //= spec/framework/branch-key-store.md#createkeystore
  //= type=implication
  //# The table MAY have additional information,
  //# like GlobalSecondaryIndex defined.
  private static boolean hasKeyStoreSchema(TableDescription table) {
    return (
      table.hasAttributeDefinitions() &&
      table.attributeDefinitions().containsAll(ATTRIBUTE_DEFINITIONS) &&
      table.hasKeySchema() &&
      table.keySchema().containsAll(KEY_SCHEMA) &&
      table.tableName() != null &&
      table.tableArn() != null &&
      !table.tableArn().isEmpty() &&
      table.tableArn().length() <= MAX_TABLE_ARN_LENGTH
    );
  }

  /** The item stored under the key; fails if there is none, and with {@code invalidItem} if it is not a valid one. */
  Map<String, AttributeValue> get(String branchKeyIdentifier, String type, String invalidItem) {
    Map<String, AttributeValue> key = new HashMap<>();
    key.put(KeyStoreItems.BRANCH_KEY_IDENTIFIER_FIELD, AttributeValue.builder().s(branchKeyIdentifier).build());
    key.put(KeyStoreItems.TYPE_FIELD, AttributeValue.builder().s(type).build());
    GetItemResponse response;
    try {
      response = ddb.getItem(r -> r.key(key).tableName(tableName));
    } catch (SdkException e) {
      throw AwsErrors.from(e);
    }
    //= spec/framework/branch-key-store.md#getactivebranchkey
    //= type=implication
    //# If the record does not contain the defined fields, this operation MUST fail.

    //= spec/framework/branch-key-store.md#getbranchkeyversion
    //= type=implication
    //# If the record does not contain the defined fields, this operation MUST fail.

    //= spec/framework/branch-key-store.md#getbeaconkey
    //= type=implication
    //# If the record does not contain the defined fields, this operation MUST fail.
    if (!response.hasItem() || response.item().isEmpty()) {
      throw new ResourceNotFoundException(KeyStoreMessages.NO_CORRESPONDING_BRANCH_KEY);
    }
    Map<String, AttributeValue> item = response.item();
    //= spec/framework/branch-key-store.md#getactivebranchkey
    //= type=implication
    //# The AWS DDB response MUST contain the fields defined in the [branch keystore record format](#record-format).

    //= spec/framework/branch-key-store.md#getbranchkeyversion
    //= type=implication
    //# The AWS DDB response MUST contain the fields defined in the [branch keystore record format](#record-format).

    //= spec/framework/branch-key-store.md#getbeaconkey
    //= type=implication
    //# The AWS DDB response MUST contain the fields defined in the [branch keystore record format](#record-format).
    if (!KeyStoreItems.isValid(item, branchKeyIdentifier, type)) {
      throw new InvalidMaterialsException(invalidItem);
    }
    return item;
  }

  /** Writes the three items of a new branch key; fails if any of them exists. */
  //= spec/framework/branch-key-store.md#writing-branch-key-and-beacon-key-to-keystore
  //= type=implication
  //# The operation MUST call Amazon DynamoDB TransactWriteItems with a request constructed as follows:
  void writeNewKey(Map<String, AttributeValue> version, Map<String, AttributeValue> active, Map<String, AttributeValue> beacon) {
    transactWrite(put(version, BRANCH_KEY_NOT_EXIST), put(active, BRANCH_KEY_NOT_EXIST), put(beacon, BRANCH_KEY_NOT_EXIST));
  }

  /** Writes a new version and replaces the ACTIVE item; fails if the version exists or the ACTIVE item does not. */
  //= spec/framework/branch-key-store.md#versionkey
  //= type=implication
  //# The operation MUST call Amazon DynamoDB TransactWriteItems with a request constructed as follows:
  void writeNewVersion(Map<String, AttributeValue> version, Map<String, AttributeValue> active) {
    transactWrite(put(version, BRANCH_KEY_NOT_EXIST), put(active, BRANCH_KEY_EXISTS));
  }

  private TransactWriteItem put(Map<String, AttributeValue> item, String condition) {
    return TransactWriteItem.builder()
      .put(p -> p.item(item).tableName(tableName).conditionExpression(condition).expressionAttributeNames(BRANCH_KEY_PLACEHOLDER_NAMES))
      .build();
  }

  //= spec/framework/branch-key-store.md#writing-branch-key-and-beacon-key-to-keystore
  //= type=implication
  //# If DDB TransactWriteItems is successful, this operation MUST return a successful response containing no additional data.

  //= spec/framework/branch-key-store.md#writing-branch-key-and-beacon-key-to-keystore
  //= type=implication
  //# Otherwise, this operation MUST yield an error.
  private void transactWrite(TransactWriteItem... items) {
    try {
      //= spec/framework/branch-key-store.md#writing-branch-key-and-beacon-key-to-keystore
      //= type=implication
      //# To add the branch keys and a beacon key to the keystore the
      //# operation MUST call [Amazon DynamoDB API TransactWriteItems](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html).

      //= spec/framework/branch-key-store.md#writing-branch-key-and-beacon-key-to-keystore
      //= type=implication
      //# The call to Amazon DynamoDB TransactWriteItems MUST use the configured Amazon DynamoDB Client to make the call.

      //= spec/framework/branch-key-store.md#versionkey
      //= type=implication
      //# The call to Amazon DynamoDB TransactWriteItems MUST use the configured Amazon DynamoDB Client to make the call.
      ddb.transactWriteItems(r -> r.transactItems(items));
    } catch (SdkException e) {
      throw AwsErrors.from(e);
    }
  }
}
