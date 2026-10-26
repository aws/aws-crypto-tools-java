// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.TABLE;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.WEST;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.config;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.get;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.keyArn;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.with;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.cryptography.oldapi.keystore.model.CreateKeyStoreInput;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.fakeaws.ServiceError;

// CreateKeyStore, native (through the adapter) against the reference, each on its own identically seeded endpoint.
class KeyStoreCreateKeyStoreTest {

  private final KeyStoreHarness harness = KeyStoreHarness.paired();
  private final String kmsKey = harness.symmetricKey(WEST);

  @AfterEach
  void close() {
    harness.close();
  }

  //= spec/framework/branch-key-store.md#createkeystore
  //= type=test
  //# If the client responds with a `ResourceNotFoundException`,
  //# then this operation MUST continue and

  //= spec/framework/branch-key-store.md#createkeystore
  //= type=test
  //# If the operation successfully creates a table, the operation MUST return the AWS DDB Table Arn
  //# back to the caller.
  @Test
  void createsAMissingTable() {
    String outcome = createKeyStore(harness.ddb(WEST));
    assertEquals("CreateKeyStoreOutput{tableArn=\"arn:aws:dynamodb:us-west-2:111122223333:table/KeyStoreTable\"}", outcome);
  }

  @Test
  void acceptsAnExistingKeyStoreTable() {
    harness.createTable(WEST);
    createKeyStore(harness.ddb(WEST));
  }

  @Test
  void createsTheTableInTheClientsRegion() {
    createKeyStore(harness.ddb(KeyStoreHarness.EAST));
  }

  //= spec/framework/branch-key-store.md#createkeystore
  //= type=test
  //# If the [KeySchema](#keyschema) does not match
  //# this operation MUST yield an error.
  @Test
  void rejectsATableWithAnotherKeySchema() {
    List<List<String>> schemas = Arrays.asList(
      Arrays.asList("branch-key-id", "S", "HASH"),
      Arrays.asList("branch-key-id", "S", "HASH", "kind", "S", "RANGE"),
      Arrays.asList("type", "S", "HASH", "branch-key-id", "S", "RANGE"),
      Arrays.asList("branch-key-id", "S", "HASH", "type", "N", "RANGE"),
      Arrays.asList("branch-key-id", "B", "HASH", "type", "S", "RANGE")
    );
    String[] tables = { "TableA", "TableB", "TableC", "TableD", "TableE" };
    for (int i = 0; i < schemas.size(); i++) {
      String table = tables[i];
      for (FakeAws aws : harness.endpoints()) {
        createTable(aws, table, schemas.get(i));
      }
      KeyStoreHarness.stores(config(keyArn(kmsKey), harness.kms(WEST), harness.ddb(WEST)).ddbTableName(table).build())
        .same("CreateKeyStore", CreateKeyStoreInput.builder().build());
    }
    harness.assertSameRequests();
  }

  //= spec/framework/branch-key-store.md#createkeystore
  //= type=test
  //# If the operation fails to create table, the operation MUST fail.
  @Test
  void serviceFailures() {
    for (FakeAws aws : harness.endpoints()) {
      aws.dynamoDb().fail("DescribeTable", ServiceError.accessDenied("no DescribeTable"));
    }
    createKeyStore(harness.ddb(WEST));
    for (FakeAws aws : harness.endpoints()) {
      aws.dynamoDb().clearFailures();
      aws.dynamoDb().fail("CreateTable", ServiceError.of("LimitExceededException", "too many tables"));
    }
    createKeyStore(harness.ddb(WEST));
    for (FakeAws aws : harness.endpoints()) {
      aws.dynamoDb().clearFailures();
      aws.dynamoDb().fail("DescribeTable", ServiceError.of("com.amazonaws.dynamodb.v20120810#InternalServerError", "boom"));
    }
    createKeyStore(harness.ddb(WEST));
  }

  // DynamoDB answers that the fake cannot produce: each response check of CreateKeyStoreTable.dfy.
  @Test
  void unexpectedDescribeTableResponses() {
    harness.createTable(WEST);
    for (Function<Object, Object> change : tableChanges()) {
      createKeyStore(harness.ddb(WEST, "describeTable", replacing("table", change)));
    }
    createKeyStore(harness.ddb(WEST, "describeTable", (call, request, proceed) -> with(proceed.get(), "table", null)));
  }

  @Test
  void unexpectedCreateTableResponses() {
    for (Function<Object, Object> change : tableChanges()) {
      // A fresh endpoint each time, so the table is missing and CreateTable runs.
      try (KeyStoreHarness fresh = KeyStoreHarness.paired()) {
        String key = fresh.symmetricKey(WEST);
        createKeyStore(fresh, key, fresh.ddb(WEST, "createTable", replacing("tableDescription", change)));
      }
    }
    try (KeyStoreHarness fresh = KeyStoreHarness.paired()) {
      String key = fresh.symmetricKey(WEST);
      createKeyStore(fresh, key, fresh.ddb(WEST, "createTable", (call, request, proceed) -> with(proceed.get(), "tableDescription", null)));
    }
  }

  private static KeyStoreHarness.Hook replacing(String field, Function<Object, Object> change) {
    return (call, request, proceed) -> {
      Object response = proceed.get();
      return with(response, field, change.apply(get(response, field)));
    };
  }

  private static List<Function<Object, Object>> tableChanges() {
    return Arrays.asList(
      table -> with(table, "tableArn", null),
      table -> with(table, "tableArn", ""),
      table -> with(table, "tableArn", "arn:aws:dynamodb:us-west-2:111122223333:table/OtherTable"),
      table -> with(table, "tableArn", "arn:aws:dynamodb:us-west-2:111122223333:index/" + TABLE),
      table -> with(table, "tableArn", "arn:aws:dynamodb:us-west-2:111122223333:table/" + TABLE + "/stream/x"),
      table -> with(table, "tableArn", "arn:aws:dynamodb:us-west-2:111122223333:" + TABLE),
      table -> with(table, "tableArn", "arn:aws:kms:us-west-2:111122223333:table/" + TABLE),
      table -> with(table, "tableArn", "arn::dynamodb:us-west-2:111122223333:table/" + TABLE),
      table -> with(table, "tableArn", "arn:aws:dynamodb::111122223333:table/" + TABLE),
      table -> with(table, "tableArn", "arn:aws:dynamodb:us-west-2::table/" + TABLE),
      table -> with(table, "tableArn", "nra:aws:dynamodb:us-west-2:111122223333:table/" + TABLE),
      table -> with(table, "tableArn", "arn:aws:dynamodb:us-west-2:111122223333:table/" + TABLE + ":x"),
      table -> with(table, "tableArn", "arn:aws:dynamodb:us-west-2:111122223333:table/ab"),
      // 1025 and 1024 characters: TableArn is at most 1024.
      table -> with(table, "tableArn", "arn:aws:dynamodb:us-west-2:" + repeat('1', 978) + ":table/" + TABLE),
      table -> with(table, "tableArn", "arn:aws:dynamodb:us-west-2:" + repeat('1', 977) + ":table/" + TABLE),
      table -> with(table, "tableName", null),
      table -> with(table, "attributeDefinitions", Collections.emptyList()),
      table -> with(table, "keySchema", Collections.emptyList()),
      table -> with(table, "attributeDefinitions", withExtra(get(table, "attributeDefinitions"), "attributeName", "extra")),
      table -> with(table, "keySchema", withExtra(get(table, "keySchema"), "attributeName", "extra")),
      table -> with(table, "attributeDefinitions", ((List<?>) get(table, "attributeDefinitions")).subList(0, 1)),
      table -> with(table, "keySchema", ((List<?>) get(table, "keySchema")).subList(1, 2))
    );
  }

  // The list plus a copy of its first element with one field changed.
  private static List<Object> withExtra(Object list, String field, Object value) {
    List<Object> extended = new java.util.ArrayList<>((List<?>) list);
    extended.add(with(extended.get(0), field, value));
    return extended;
  }

  private String createKeyStore(DynamoDbClient ddb) {
    return createKeyStore(harness, kmsKey, ddb);
  }

  private static String createKeyStore(KeyStoreHarness harness, String kmsKey, DynamoDbClient ddb) {
    harness.clearRequests();
    String outcome = KeyStoreHarness.stores(config(keyArn(kmsKey), harness.kms(WEST), ddb).build())
      .same("CreateKeyStore", CreateKeyStoreInput.builder().build());
    harness.assertSameRequests();
    return outcome;
  }

  // Attribute name, type, and key type triples.
  private static void createTable(FakeAws aws, String table, List<String> schema) {
    KeySchemaElement[] keys = new KeySchemaElement[schema.size() / 3];
    AttributeDefinition[] definitions = new AttributeDefinition[schema.size() / 3];
    for (int i = 0; i < keys.length; i++) {
      String name = schema.get(3 * i);
      String type = schema.get(3 * i + 1);
      String keyType = schema.get(3 * i + 2);
      keys[i] = KeySchemaElement.builder().attributeName(name).keyType(keyType).build();
      definitions[i] = AttributeDefinition.builder().attributeName(name).attributeType(type).build();
    }
    aws
      .dynamoDbClient("setup", WEST)
      .createTable(r -> r.tableName(table).billingMode("PAY_PER_REQUEST").keySchema(keys).attributeDefinitions(definitions));
  }

  private static String repeat(char c, int count) {
    char[] chars = new char[count];
    Arrays.fill(chars, c);
    return new String(chars);
  }
}
