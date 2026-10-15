// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.fakeaws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CancellationReason;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.CreateTableResponse;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ResourceInUseException;
import software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import software.amazon.awssdk.services.dynamodb.model.TableDescription;
import software.amazon.awssdk.services.dynamodb.model.TableStatus;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;
import software.amazon.awssdk.services.dynamodb.model.TransactionCanceledException;

// The fake DynamoDB through this module's AWS SDK, using the request shapes of the MPL key store.
class FakeDynamoDbTest {

  private static final String REGION = "us-west-2";
  private static final String TABLE = "KeyStoreTable";
  private static final String HASH = "branch-key-id";
  private static final String RANGE = "type";
  private static final String NOT_EXISTS = "attribute_not_exists(#BranchKeyIdentifierField)";
  private static final String EXISTS = "attribute_exists(#BranchKeyIdentifierField)";

  private final FakeAws aws = FakeAws.start();
  private final DynamoDbClient ddb = aws.dynamoDbClient("ddb", REGION);

  @AfterEach
  void close() {
    aws.close();
  }

  @Test
  void createAndDescribeTable() {
    assertThrows(ResourceNotFoundException.class, () -> ddb.describeTable(r -> r.tableName(TABLE)));
    CreateTableResponse created = createTable();
    String arn = "arn:aws:dynamodb:" + REGION + ":" + FakeKms.ACCOUNT + ":table/" + TABLE;
    assertEquals(arn, created.tableDescription().tableArn());
    assertEquals(TableStatus.CREATING, created.tableDescription().tableStatus());

    TableDescription described = ddb.describeTable(r -> r.tableName(TABLE)).table();
    assertEquals(TABLE, described.tableName());
    assertEquals(arn, described.tableArn());
    assertEquals(TableStatus.ACTIVE, described.tableStatus());
    assertEquals(created.tableDescription().keySchema(), described.keySchema());
    assertEquals(created.tableDescription().attributeDefinitions(), described.attributeDefinitions());
    assertEquals(BillingMode.PAY_PER_REQUEST, described.billingModeSummary().billingMode());

    assertThrows(ResourceInUseException.class, this::createTable);
    // Tables are per region.
    DynamoDbClient east = aws.dynamoDbClient("ddb", "us-east-1");
    assertThrows(ResourceNotFoundException.class, () -> east.describeTable(r -> r.tableName(TABLE)));
    assertThrows(ResourceNotFoundException.class, () -> east.getItem(r -> r.tableName(TABLE).key(key("a", "b"))));
  }

  @Test
  void putAndGetEveryAttributeType() {
    createTable();
    Map<String, AttributeValue> item = new HashMap<>(key("id", "branch:ACTIVE"));
    item.put("hierarchy-version", AttributeValue.fromN("1"));
    item.put("enc", AttributeValue.fromB(SdkBytes.fromByteArray(new byte[] { 0, 1, (byte) 255 })));
    item.put("kms-arn", AttributeValue.fromS("arn:aws:kms:us-west-2:111122223333:key/k"));
    item.put("nested", AttributeValue.fromM(Collections.singletonMap("x", AttributeValue.fromBool(true))));
    item.put("list", AttributeValue.fromL(Arrays.asList(AttributeValue.fromS("a"), AttributeValue.fromNul(true))));
    ddb.putItem(r -> r.tableName(TABLE).item(item));

    for (boolean consistent : new boolean[] { true, false }) {
      assertEquals(item, ddb.getItem(r -> r.tableName(TABLE).key(key("id", "branch:ACTIVE")).consistentRead(consistent)).item());
    }
    assertFalse(ddb.getItem(r -> r.tableName(TABLE).key(key("id", "beacon:ACTIVE"))).hasItem());
    assertFalse(ddb.getItem(r -> r.tableName(TABLE).key(key("other", "branch:ACTIVE"))).hasItem());

    // A put replaces the whole item.
    ddb.putItem(r -> r.tableName(TABLE).item(key("id", "branch:ACTIVE")));
    assertEquals(key("id", "branch:ACTIVE"), ddb.getItem(r -> r.tableName(TABLE).key(key("id", "branch:ACTIVE"))).item());
  }

  @Test
  void keysMustMatchTheSchema() {
    createTable();
    Map<String, AttributeValue> numberType = new HashMap<>();
    numberType.put(HASH, AttributeValue.fromN("1"));
    numberType.put(RANGE, AttributeValue.fromS("t"));
    Map<String, AttributeValue> extra = new HashMap<>(key("id", "t"));
    extra.put("enc", AttributeValue.fromS("x"));
    for (Map<String, AttributeValue> bad : Arrays.asList(numberType, extra, Collections.singletonMap(HASH, AttributeValue.fromS("id")))) {
      assertEquals("ValidationException", errorCode(() -> ddb.getItem(r -> r.tableName(TABLE).key(bad))), bad.toString());
    }
    assertEquals("ValidationException", errorCode(() -> ddb.putItem(r -> r.tableName(TABLE).item(numberType))));
    assertEquals(
      "ValidationException",
      errorCode(() -> ddb.putItem(r -> r.tableName(TABLE).item(Collections.singletonMap(HASH, AttributeValue.fromS("id")))))
    );
    assertThrows(ResourceNotFoundException.class, () -> ddb.putItem(r -> r.tableName("Missing").item(key("id", "t"))));
  }

  @Test
  void putItemConditions() {
    createTable();
    ddb.putItem(r -> r.tableName(TABLE).item(key("id", "t")).conditionExpression(NOT_EXISTS).expressionAttributeNames(names()));
    ConditionalCheckFailedException failed = assertThrows(
      ConditionalCheckFailedException.class,
      () -> ddb.putItem(r -> r.tableName(TABLE).item(key("id", "t")).conditionExpression(NOT_EXISTS).expressionAttributeNames(names()))
    );
    assertEquals("The conditional request failed", failed.awsErrorDetails().errorMessage());
    ddb.putItem(r -> r.tableName(TABLE).item(key("id", "t")).conditionExpression(EXISTS).expressionAttributeNames(names()));
    assertThrows(
      ConditionalCheckFailedException.class,
      () -> ddb.putItem(r -> r.tableName(TABLE).item(key("id", "u")).conditionExpression(EXISTS).expressionAttributeNames(names()))
    );
    // A plain attribute name, and a non-key attribute.
    ddb.putItem(r -> r.tableName(TABLE).item(key("id", "u")).conditionExpression("attribute_not_exists(enc)"));
    assertThrows(
      ConditionalCheckFailedException.class,
      () -> ddb.putItem(r -> r.tableName(TABLE).item(key("id", "u")).conditionExpression("attribute_exists(enc)"))
    );
  }

  @Test
  void unsupportedOrInvalidExpressionsFail() {
    createTable();
    Map<String, String> twoNames = new HashMap<>(names());
    twoNames.put("#unused", "x");
    assertEquals(
      "ValidationException",
      errorCode(() -> ddb.putItem(r -> r.tableName(TABLE).item(key("id", "t")).conditionExpression(NOT_EXISTS).expressionAttributeNames(twoNames)))
    );
    assertEquals(
      "ValidationException",
      errorCode(() -> ddb.putItem(r -> r.tableName(TABLE).item(key("id", "t")).conditionExpression("attribute_not_exists(#undefined)")))
    );
    assertEquals("ValidationException", errorCode(() -> ddb.putItem(r -> r.tableName(TABLE).item(key("id", "t")).expressionAttributeNames(names()))));
    assertEquals(
      "ValidationException",
      errorCode(() -> ddb.putItem(r -> r.tableName(TABLE).item(key("id", "t")).conditionExpression("size(enc) > :n")))
    );
    DynamoDbException unsupported = assertThrows(
      DynamoDbException.class,
      () -> ddb.getItem(r -> r.tableName(TABLE).key(key("id", "t")).projectionExpression("enc"))
    );
    assertEquals("the fake DynamoDB does not support request field ProjectionExpression", unsupported.awsErrorDetails().errorMessage());
    assertFalse(ddb.getItem(r -> r.tableName(TABLE).key(key("id", "t"))).hasItem());
  }

  @Test
  void transactWriteItemsIsAllOrNothing() {
    createTable();
    List<TransactWriteItem> create = Arrays.asList(
      put(key("id", "branch:version:1"), NOT_EXISTS),
      put(key("id", "branch:ACTIVE"), NOT_EXISTS),
      put(key("id", "beacon:ACTIVE"), NOT_EXISTS)
    );
    ddb.transactWriteItems(r -> r.transactItems(create));
    for (TransactWriteItem write : create) {
      assertTrue(ddb.getItem(r -> r.tableName(TABLE).key(write.put().item())).hasItem());
    }

    TransactionCanceledException cancelled = assertThrows(
      TransactionCanceledException.class,
      () -> ddb.transactWriteItems(r -> r.transactItems(put(key("id", "branch:version:2"), NOT_EXISTS), put(key("id", "branch:ACTIVE"), NOT_EXISTS)))
    );
    assertEquals(Arrays.asList("None", "ConditionalCheckFailed"), codes(cancelled.cancellationReasons()));
    assertEquals(
      "Transaction cancelled, please refer cancellation reasons for specific reasons [None, ConditionalCheckFailed]",
      cancelled.awsErrorDetails().errorMessage()
    );
    // The write whose condition held was not applied.
    assertFalse(ddb.getItem(r -> r.tableName(TABLE).key(key("id", "branch:version:2"))).hasItem());

    // The shape of a version rotation: a new version, and the active item that must exist.
    ddb.transactWriteItems(r -> r.transactItems(put(key("id", "branch:version:2"), NOT_EXISTS), put(key("id", "branch:ACTIVE"), EXISTS)));
    TransactionCanceledException missing = assertThrows(
      TransactionCanceledException.class,
      () -> ddb.transactWriteItems(r -> r.transactItems(put(key("new", "branch:version:1"), NOT_EXISTS), put(key("new", "branch:ACTIVE"), EXISTS)))
    );
    assertEquals(Arrays.asList("None", "ConditionalCheckFailed"), codes(missing.cancellationReasons()));

    assertEquals(
      "ValidationException",
      errorCode(() -> ddb.transactWriteItems(r -> r.transactItems(put(key("x", "t"), NOT_EXISTS), put(key("x", "t"), NOT_EXISTS))))
    );
    assertEquals(
      "ValidationException",
      errorCode(() -> ddb.transactWriteItems(r -> r.transactItems(TransactWriteItem.builder().delete(d -> d.tableName(TABLE).key(key("id", "t"))).build())))
    );
    assertThrows(
      ResourceNotFoundException.class,
      () -> ddb.transactWriteItems(r -> r.transactItems(TransactWriteItem.builder().put(p -> p.tableName("Missing").item(key("x", "t"))).build()))
    );
  }

  @Test
  void injectedFailures() {
    aws.dynamoDb().fail("DescribeTable", ServiceError.accessDenied("no dynamodb:DescribeTable"));
    DynamoDbException denied = assertThrows(DynamoDbException.class, () -> ddb.describeTable(r -> r.tableName(TABLE)));
    assertEquals("AccessDeniedException", denied.awsErrorDetails().errorCode());
    assertEquals("no dynamodb:DescribeTable", denied.awsErrorDetails().errorMessage());
    createTable();
    aws.dynamoDb().fail("GetItem", ServiceError.throttling("slow down"));
    assertEquals("ThrottlingException", errorCode(() -> ddb.getItem(r -> r.tableName(TABLE).key(key("id", "t")))));
    assertEquals(1, aws.requests("ddb").stream().filter(r -> r.operation().equals("GetItem")).count());
    aws.dynamoDb().clearFailures();
    ddb.describeTable(r -> r.tableName(TABLE));
    ddb.getItem(r -> r.tableName(TABLE).key(key("id", "t")));
  }

  @Test
  void requestsAreRecorded() {
    createTable();
    ddb.getItem(r -> r.tableName(TABLE).key(key("id", "t")).consistentRead(true));
    ddb.transactWriteItems(r -> r.transactItems(TransactWriteItem.builder().put(p -> p.tableName(TABLE).item(key("id", "t"))).build()));
    List<RecordedRequest> requests = aws.requests("ddb");
    assertEquals(3, requests.size());
    assertEquals("CreateTable", requests.get(0).operation());
    assertEquals(
      "dynamodb GetItem us-west-2 {\"ConsistentRead\":true,\"Key\":{\"branch-key-id\":{\"S\":\"id\"},\"type\":{\"S\":\"t\"}},\"TableName\":\"KeyStoreTable\"}",
      requests.get(1).describe()
    );
    // Without the SDK's random ClientRequestToken.
    assertEquals(
      "dynamodb TransactWriteItems us-west-2 {\"TransactItems\":[{\"Put\":{\"Item\":{\"branch-key-id\":{\"S\":\"id\"},\"type\":{\"S\":\"t\"}},\"TableName\":\"KeyStoreTable\"}}]}",
      requests.get(2).describe()
    );
  }

  private CreateTableResponse createTable() {
    return ddb.createTable(r ->
      r
        .tableName(TABLE)
        .billingMode(BillingMode.PAY_PER_REQUEST)
        .keySchema(
          KeySchemaElement.builder().attributeName(HASH).keyType(KeyType.HASH).build(),
          KeySchemaElement.builder().attributeName(RANGE).keyType(KeyType.RANGE).build()
        )
        .attributeDefinitions(
          AttributeDefinition.builder().attributeName(HASH).attributeType(ScalarAttributeType.S).build(),
          AttributeDefinition.builder().attributeName(RANGE).attributeType(ScalarAttributeType.S).build()
        )
    );
  }

  private static TransactWriteItem put(Map<String, AttributeValue> item, String condition) {
    return TransactWriteItem.builder()
      .put(p -> p.tableName(TABLE).item(item).conditionExpression(condition).expressionAttributeNames(names()))
      .build();
  }

  private static Map<String, String> names() {
    return Collections.singletonMap("#BranchKeyIdentifierField", HASH);
  }

  private static Map<String, AttributeValue> key(String id, String type) {
    Map<String, AttributeValue> key = new HashMap<>();
    key.put(HASH, AttributeValue.fromS(id));
    key.put(RANGE, AttributeValue.fromS(type));
    return key;
  }

  private static List<String> codes(List<CancellationReason> reasons) {
    String[] codes = new String[reasons.size()];
    for (int i = 0; i < codes.length; i++) {
      codes[i] = reasons.get(i).code();
    }
    return Arrays.asList(codes);
  }

  private static String errorCode(Runnable call) {
    return assertThrows(DynamoDbException.class, call::run).awsErrorDetails().errorCode();
  }
}
