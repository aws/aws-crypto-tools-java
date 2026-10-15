// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.fakeaws;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The DynamoDB half of {@link FakeAws}: the operations the MPL key store calls.
 *
 * <p>Supported: CreateTable, DescribeTable, GetItem, PutItem, and TransactWriteItems of Put items.
 * Condition expressions are {@code attribute_exists(path)} and {@code attribute_not_exists(path)},
 * where the path is an attribute name or an {@code ExpressionAttributeNames} placeholder.
 * A request field outside that subset fails with ValidationException naming the field,
 * so a caller that starts to depend on more of DynamoDB fails loudly instead of being served wrongly.
 *
 * <p>Tables are per region. Attribute values are stored as the JSON the client sent,
 * so every attribute type round-trips; key attributes must be S, N, or B as the table defines.
 * Writes are immediately visible, so consistent and eventually consistent reads see the same items.
 */
public final class FakeDynamoDb {

  private static final String ERROR_PREFIX = "com.amazonaws.dynamodb.v20120810#";
  private static final Pattern TABLE_NAME = Pattern.compile("[a-zA-Z0-9_.-]{3,255}");
  private static final Pattern CONDITION = Pattern.compile(
    "\\s*(attribute_exists|attribute_not_exists)\\s*\\(\\s*(#?[A-Za-z0-9_-]+)\\s*\\)\\s*"
  );

  private final Map<String, Table> tables = new HashMap<>();
  private final Map<String, ServiceError> failures = new HashMap<>();

  FakeDynamoDb() {}

  /** Makes every later {@code operation} request fail with {@code error}, until {@link #clearFailures}. */
  public synchronized void fail(String operation, ServiceError error) {
    failures.put(operation, error);
  }

  public synchronized void clearFailures() {
    failures.clear();
  }

  synchronized JsonNode handle(String operation, String region, ObjectNode request) {
    ServiceError failure = failures.get(operation);
    if (failure != null) {
      throw failure;
    }
    switch (operation) {
      case "CreateTable":
        return createTable(region, request);
      case "DescribeTable":
        return describeTable(region, request);
      case "GetItem":
        return getItem(region, request);
      case "PutItem":
        return putItem(region, request);
      case "TransactWriteItems":
        return transactWriteItems(region, request);
      default:
        throw ServiceError.of(ERROR_PREFIX + "UnknownOperationException", "the fake DynamoDB does not implement " + operation);
    }
  }

  private JsonNode createTable(String region, ObjectNode request) {
    allowOnly(request, "TableName", "KeySchema", "AttributeDefinitions", "BillingMode");
    String name = tableName(request);
    JsonNode billingMode = request.get("BillingMode");
    if (billingMode == null || !billingMode.asText().equals("PAY_PER_REQUEST")) {
      throw validation("the fake DynamoDB supports only BillingMode PAY_PER_REQUEST");
    }
    if (tables.containsKey(region + "/" + name)) {
      throw ServiceError.of(ERROR_PREFIX + "ResourceInUseException", "Table already exists: " + name);
    }
    JsonNode keySchema = required(request, "KeySchema");
    JsonNode definitions = required(request, "AttributeDefinitions");
    Map<String, String> types = new LinkedHashMap<>();
    for (JsonNode definition : definitions) {
      types.put(required(definition, "AttributeName").asText(), required(definition, "AttributeType").asText());
    }
    List<String> keyNames = new ArrayList<>();
    for (JsonNode element : keySchema) {
      String keyType = required(element, "KeyType").asText();
      if (!keyType.equals(keyNames.isEmpty() ? "HASH" : "RANGE")) {
        throw validation("Invalid KeySchema: The first KeySchemaElement is not a HASH key type");
      }
      keyNames.add(required(element, "AttributeName").asText());
    }
    if (keyNames.isEmpty() || keyNames.size() > 2) {
      throw validation("Invalid KeySchema: Some index key schema element is not valid");
    }
    if (!types.keySet().equals(new HashSet<>(keyNames))) {
      throw validation(
        "One or more parameter values were invalid: Number of attributes in KeySchema does not exactly match " +
          "number of attributes defined in AttributeDefinitions"
      );
    }
    Table table = new Table(name, "arn:aws:dynamodb:" + region + ":" + FakeKms.ACCOUNT + ":table/" + name, keyNames, types, keySchema, definitions);
    tables.put(region + "/" + name, table);
    ObjectNode response = JsonNodeFactory.instance.objectNode();
    response.set("TableDescription", table.description("CREATING"));
    return response;
  }

  private JsonNode describeTable(String region, ObjectNode request) {
    allowOnly(request, "TableName");
    String name = tableName(request);
    Table table = tables.get(region + "/" + name);
    if (table == null) {
      throw resourceNotFound("Requested resource not found: Table: " + name + " not found");
    }
    ObjectNode response = JsonNodeFactory.instance.objectNode();
    response.set("Table", table.description("ACTIVE"));
    return response;
  }

  private JsonNode getItem(String region, ObjectNode request) {
    allowOnly(request, "TableName", "Key", "ConsistentRead");
    Table table = table(region, request);
    JsonNode key = required(request, "Key");
    if (key.size() != table.keyNames.size()) {
      throw validation("The provided key element does not match the schema");
    }
    ObjectNode item = table.items.get(table.keyOf(key, "The provided key element does not match the schema"));
    ObjectNode response = JsonNodeFactory.instance.objectNode();
    if (item != null) {
      response.set("Item", item);
    }
    return response;
  }

  private JsonNode putItem(String region, ObjectNode request) {
    allowOnly(request, "TableName", "Item", "ConditionExpression", "ExpressionAttributeNames");
    Write write = write(region, request);
    if (!write.conditionHolds()) {
      throw ServiceError.of(ERROR_PREFIX + "ConditionalCheckFailedException", "The conditional request failed");
    }
    write.apply();
    return JsonNodeFactory.instance.objectNode();
  }

  // All conditions are checked before any write, so a failed transaction changes nothing.
  private JsonNode transactWriteItems(String region, ObjectNode request) {
    // The SDK fills ClientRequestToken with a random idempotency token; every call is new, so it has no effect here.
    allowOnly(request, "TransactItems", "ClientRequestToken");
    JsonNode items = required(request, "TransactItems");
    if (items.size() < 1 || items.size() > 100) {
      throw validation("Member must have length less than or equal to 100 and greater than or equal to 1: TransactItems");
    }
    List<Write> writes = new ArrayList<>();
    Set<String> targets = new HashSet<>();
    for (JsonNode element : items) {
      allowOnly((ObjectNode) element, "Put");
      JsonNode put = required(element, "Put");
      allowOnly((ObjectNode) put, "TableName", "Item", "ConditionExpression", "ExpressionAttributeNames");
      Write write = write(region, (ObjectNode) put);
      if (!targets.add(write.table.arn + " " + write.key)) {
        throw validation("Transaction request cannot include multiple operations on one item");
      }
      writes.add(write);
    }
    List<String> codes = new ArrayList<>();
    ArrayNode reasons = JsonNodeFactory.instance.arrayNode();
    boolean cancelled = false;
    for (Write write : writes) {
      ObjectNode reason = reasons.addObject();
      if (write.conditionHolds()) {
        reason.put("Code", "None");
        codes.add("None");
      } else {
        reason.put("Code", "ConditionalCheckFailed");
        reason.put("Message", "The conditional request failed");
        codes.add("ConditionalCheckFailed");
        cancelled = true;
      }
    }
    if (cancelled) {
      ObjectNode extra = JsonNodeFactory.instance.objectNode();
      extra.set("CancellationReasons", reasons);
      throw ServiceError.withFields(
        ERROR_PREFIX + "TransactionCanceledException",
        "Transaction cancelled, please refer cancellation reasons for specific reasons " + codes,
        extra
      );
    }
    for (Write write : writes) {
      write.apply();
    }
    return JsonNodeFactory.instance.objectNode();
  }

  private Write write(String region, ObjectNode request) {
    Table table = table(region, request);
    JsonNode item = required(request, "Item");
    if (!item.isObject()) {
      throw ServiceError.of("SerializationException", "Item is not a JSON object");
    }
    String key = table.keyOf(item, null);
    JsonNode names = request.get("ExpressionAttributeNames");
    JsonNode expression = request.get("ConditionExpression");
    Condition condition = null;
    if (expression == null) {
      if (names != null) {
        throw validation("ExpressionAttributeNames can only be specified when using expressions");
      }
    } else {
      condition = condition(expression.asText(), names);
    }
    return new Write(table, key, (ObjectNode) item, condition);
  }

  private static Condition condition(String expression, JsonNode names) {
    Matcher matcher = CONDITION.matcher(expression);
    if (!matcher.matches()) {
      throw validation("the fake DynamoDB supports only attribute_exists(path) and attribute_not_exists(path): " + expression);
    }
    String path = matcher.group(2);
    String attribute = path;
    if (path.startsWith("#")) {
      JsonNode name = names == null ? null : names.get(path);
      if (name == null) {
        throw validation(
          "Invalid ConditionExpression: An expression attribute name used in the document path is not defined; attribute name: " + path
        );
      }
      attribute = name.asText();
    }
    if (names != null) {
      Set<String> unused = new TreeSet<>();
      Iterator<String> placeholders = names.fieldNames();
      while (placeholders.hasNext()) {
        String placeholder = placeholders.next();
        if (!placeholder.equals(path)) {
          unused.add(placeholder);
        }
      }
      if (!unused.isEmpty()) {
        throw validation("Value provided in ExpressionAttributeNames unused in expressions: keys: {" + String.join(", ", unused) + "}");
      }
    }
    return new Condition(matcher.group(1).equals("attribute_exists"), attribute);
  }

  private Table table(String region, ObjectNode request) {
    Table table = tables.get(region + "/" + tableName(request));
    if (table == null) {
      throw resourceNotFound("Requested resource not found");
    }
    return table;
  }

  private static String tableName(JsonNode request) {
    String name = required(request, "TableName").asText();
    if (!TABLE_NAME.matcher(name).matches()) {
      throw validation("1 validation error detected: Value '" + name + "' at 'tableName' failed to satisfy constraint");
    }
    return name;
  }

  private static void allowOnly(ObjectNode request, String... allowed) {
    Set<String> allowedFields = new HashSet<>(Arrays.asList(allowed));
    Iterator<String> fields = request.fieldNames();
    while (fields.hasNext()) {
      String field = fields.next();
      if (!allowedFields.contains(field)) {
        throw validation("the fake DynamoDB does not support request field " + field);
      }
    }
  }

  private static JsonNode required(JsonNode request, String field) {
    JsonNode value = request.get(field);
    if (value == null || value.isNull()) {
      throw validation("1 validation error detected: Value null at '" + field + "' failed to satisfy constraint: Member must not be null");
    }
    return value;
  }

  private static ServiceError validation(String message) {
    return ServiceError.of(ERROR_PREFIX + "ValidationException", message);
  }

  private static ServiceError resourceNotFound(String message) {
    return ServiceError.of(ERROR_PREFIX + "ResourceNotFoundException", message);
  }

  private static final class Table {

    final String name;
    final String arn;
    final List<String> keyNames;
    final Map<String, String> keyTypes;
    final JsonNode keySchema;
    final JsonNode attributeDefinitions;
    final Map<String, ObjectNode> items = new LinkedHashMap<>();

    Table(String name, String arn, List<String> keyNames, Map<String, String> keyTypes, JsonNode keySchema, JsonNode attributeDefinitions) {
      this.name = name;
      this.arn = arn;
      this.keyNames = keyNames;
      this.keyTypes = keyTypes;
      this.keySchema = keySchema;
      this.attributeDefinitions = attributeDefinitions;
    }

    ObjectNode description(String status) {
      ObjectNode description = JsonNodeFactory.instance.objectNode();
      description.put("TableName", name);
      description.put("TableArn", arn);
      description.put("TableStatus", status);
      description.set("KeySchema", keySchema.deepCopy());
      description.set("AttributeDefinitions", attributeDefinitions.deepCopy());
      description.putObject("BillingModeSummary").put("BillingMode", "PAY_PER_REQUEST");
      return description;
    }

    // The key attribute values in schema order, rendered as JSON.
    // keyMismatch is the message for a key that does not fit the schema; null means "item" messages.
    String keyOf(JsonNode attributes, String keyMismatch) {
      ArrayNode key = JsonNodeFactory.instance.arrayNode();
      for (String keyName : keyNames) {
        JsonNode value = attributes.get(keyName);
        String type = keyTypes.get(keyName);
        if (value == null) {
          throw validation(keyMismatch != null ? keyMismatch : "One or more parameter values were invalid: Missing the key " + keyName + " in the item");
        }
        if (value.size() != 1 || !value.has(type)) {
          throw validation(
            keyMismatch != null
              ? keyMismatch
              : "One or more parameter values were invalid: Type mismatch for key " + keyName + " expected: " + type
          );
        }
        key.add(value);
      }
      return key.toString();
    }
  }

  private static final class Condition {

    final boolean exists;
    final String attribute;

    Condition(boolean exists, String attribute) {
      this.exists = exists;
      this.attribute = attribute;
    }
  }

  private static final class Write {

    final Table table;
    final String key;
    final ObjectNode item;
    final Condition condition;

    Write(Table table, String key, ObjectNode item, Condition condition) {
      this.table = table;
      this.key = key;
      this.item = item;
      this.condition = condition;
    }

    boolean conditionHolds() {
      if (condition == null) {
        return true;
      }
      ObjectNode existing = table.items.get(key);
      return (existing != null && existing.has(condition.attribute)) == condition.exists;
    }

    void apply() {
      table.items.put(key, item);
    }
  }
}
