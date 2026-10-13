package software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BatchExecuteStatementRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchExecuteStatementResponse;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.BatchStatementRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemResponse;
import software.amazon.awssdk.services.dynamodb.model.ConditionCheck;
import software.amazon.awssdk.services.dynamodb.model.Delete;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemResponse;
import software.amazon.awssdk.services.dynamodb.model.ExecuteStatementRequest;
import software.amazon.awssdk.services.dynamodb.model.ExecuteStatementResponse;
import software.amazon.awssdk.services.dynamodb.model.ExecuteTransactionRequest;
import software.amazon.awssdk.services.dynamodb.model.ExecuteTransactionResponse;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.ItemResponse;
import software.amazon.awssdk.services.dynamodb.model.ParameterizedStatement;
import software.amazon.awssdk.services.dynamodb.model.Put;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryResponse;
import software.amazon.awssdk.services.dynamodb.model.ReturnValue;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import software.amazon.awssdk.services.dynamodb.model.TransactGetItem;
import software.amazon.awssdk.services.dynamodb.model.TransactGetItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactGetItemsResponse;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsResponse;
import software.amazon.awssdk.services.dynamodb.model.Update;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemResponse;
import software.amazon.awssdk.services.dynamodb.model.WriteRequest;
import software.amazon.cryptography.dbesdk.dynamodbitemencryptor.PlaintextOverride;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction;

/**
 * The DynamoDB-SDK integration layer: wraps DynamoDB request/response objects,
 * encrypting items before a write reaches DynamoDB and decrypting them after a
 * read. Mirrors the Dafny {@code DynamoDbEncryptionTransforms} middleware; see
 * the DynamoDbEncryptionTransforms behavior spec.
 *
 * <p>Searchable encryption (beacons) is not part of this build: every table is
 * configured without a search config, so the beacon-support steps
 * ({@link #addSignedBeacons}, {@link #encryptedBeacons}, {@link #removeBeacons})
 * are identity/empty. They are kept as explicit seams so the beacon layer slots
 * in without reshaping the call sites.
 *
 * <p>Each transform leaves a request/response for an unconfigured table
 * unchanged, so one client can front a mix of encrypted and plain tables.
 */
public final class DynamoDbEncryptionTransforms {

    private static final String BEACON_PREFIX = "aws_dbe_";

    private final Map<String, TableConfig> tableConfigs;

    public DynamoDbEncryptionTransforms(Map<String, TableConfig> tableConfigs) {
        this.tableConfigs = Map.copyOf(tableConfigs);
    }

    // --- PutItem ---------------------------------------------------------

    public PutItemRequest putItemInputTransform(PutItemRequest sdkInput) {
        if (isPlainWrite(sdkInput.tableName())) {
            return sdkInput;
        }
        TableConfig table = tableConfigs.get(sdkInput.tableName());
        rejectLegacyWriteParameters(sdkInput.hasExpected(), sdkInput.conditionalOperator() != null);
        testConditionExpression(table, sdkInput.conditionExpression(), sdkInput.expressionAttributeNames());
        return sdkInput.toBuilder().item(encryptForWrite(table, sdkInput.item())).build();
    }

    public PutItemResponse putItemOutputTransform(PutItemRequest originalInput, PutItemResponse sdkOutput) {
        TableConfig table = tableConfigs.get(originalInput.tableName());
        if (table == null || !sdkOutput.hasAttributes() || sdkOutput.attributes().isEmpty()) {
            return sdkOutput;
        }
        Map<String, AttributeValue> plaintext = removeBeacons(table, table.itemCryptor().decryptItem(sdkOutput.attributes()));
        return sdkOutput.toBuilder().attributes(plaintext).build();
    }

    // --- GetItem ---------------------------------------------------------

    public GetItemRequest getItemInputTransform(GetItemRequest sdkInput) {
        return sdkInput;
    }

    public GetItemResponse getItemOutputTransform(GetItemRequest originalInput, GetItemResponse sdkOutput) {
        TableConfig table = tableConfigs.get(originalInput.tableName());
        if (table == null || !sdkOutput.hasItem() || sdkOutput.item().isEmpty()) {
            return sdkOutput;
        }
        Map<String, AttributeValue> plaintext = removeBeacons(table, table.itemCryptor().decryptItem(sdkOutput.item()));
        return sdkOutput.toBuilder().item(plaintext).build();
    }

    // --- DeleteItem ------------------------------------------------------

    public DeleteItemRequest deleteItemInputTransform(DeleteItemRequest sdkInput) {
        TableConfig table = tableConfigs.get(sdkInput.tableName());
        if (table != null) {
            rejectLegacyWriteParameters(sdkInput.hasExpected(), sdkInput.conditionalOperator() != null);
            testConditionExpression(table, sdkInput.conditionExpression(), sdkInput.expressionAttributeNames());
        }
        return sdkInput;
    }

    public DeleteItemResponse deleteItemOutputTransform(DeleteItemRequest originalInput, DeleteItemResponse sdkOutput) {
        TableConfig table = tableConfigs.get(originalInput.tableName());
        if (table == null || !sdkOutput.hasAttributes() || sdkOutput.attributes().isEmpty()) {
            return sdkOutput;
        }
        Map<String, AttributeValue> plaintext = removeBeacons(table, table.itemCryptor().decryptItem(sdkOutput.attributes()));
        return sdkOutput.toBuilder().attributes(plaintext).build();
    }

    // --- BatchGetItem ----------------------------------------------------

    public BatchGetItemRequest batchGetItemInputTransform(BatchGetItemRequest sdkInput) {
        return sdkInput;
    }

    public BatchGetItemResponse batchGetItemOutputTransform(
            BatchGetItemRequest originalInput, BatchGetItemResponse sdkOutput) {
        if (!sdkOutput.hasResponses() || sdkOutput.responses().isEmpty()) {
            return sdkOutput;
        }
        Map<String, List<Map<String, AttributeValue>>> result = new LinkedHashMap<>();
        sdkOutput.responses().forEach((tableName, items) -> {
            TableConfig table = tableConfigs.get(tableName);
            if (table == null) {
                result.put(tableName, items);
            } else {
                List<Map<String, AttributeValue>> decrypted = new ArrayList<>(items.size());
                for (Map<String, AttributeValue> item : items) {
                    decrypted.add(removeBeacons(table, table.itemCryptor().decryptItem(item)));
                }
                result.put(tableName, decrypted);
            }
        });
        return sdkOutput.toBuilder().responses(result).build();
    }

    // --- TransactGetItems ------------------------------------------------

    public TransactGetItemsRequest transactGetItemsInputTransform(TransactGetItemsRequest sdkInput) {
        return sdkInput;
    }

    public TransactGetItemsResponse transactGetItemsOutputTransform(
            TransactGetItemsRequest originalInput, TransactGetItemsResponse sdkOutput) {
        if (!sdkOutput.hasResponses() || sdkOutput.responses().isEmpty()) {
            return sdkOutput;
        }
        List<ItemResponse> encrypted = sdkOutput.responses();
        List<TransactGetItem> requested = originalInput.transactItems();
        if (encrypted.size() != requested.size()) {
            throw new DynamoDbEncryptionTransformsException(
                "Invalid TransactGetItems response for original request: Number of items returned "
                    + "must equal number of items requested.");
        }
        List<ItemResponse> result = new ArrayList<>(encrypted.size());
        for (int i = 0; i < encrypted.size(); i++) {
            String tableName = requested.get(i).get().tableName();
            TableConfig table = tableConfigs.get(tableName);
            ItemResponse response = encrypted.get(i);
            if (table == null || response.item() == null || response.item().isEmpty()) {
                result.add(response);
            } else {
                Map<String, AttributeValue> plaintext =
                    removeBeacons(table, table.itemCryptor().decryptItem(response.item()));
                result.add(ItemResponse.builder().item(plaintext).build());
            }
        }
        return sdkOutput.toBuilder().responses(result).build();
    }

    // --- UpdateItem ------------------------------------------------------

    public UpdateItemRequest updateItemInputTransform(UpdateItemRequest sdkInput) {
        TableConfig table = tableConfigs.get(sdkInput.tableName());
        if (table != null) {
            if (sdkInput.hasExpected()) {
                throw new DynamoDbEncryptionTransformsException(
                    "Legacy parameter 'Expected' not supported with Encryption.");
            }
            if (sdkInput.hasAttributeUpdates()) {
                throw new DynamoDbEncryptionTransformsException(
                    "Legacy parameter 'AttributeUpdates' not supported with Encryption.");
            }
            if (sdkInput.conditionalOperator() != null) {
                throw new DynamoDbEncryptionTransformsException(
                    "Legacy parameter 'ConditionalOperator' not supported with Encryption.");
            }
            testUpdateExpression(table, sdkInput.updateExpression(), sdkInput.expressionAttributeNames());
        }
        return sdkInput;
    }

    public UpdateItemResponse updateItemOutputTransform(
            UpdateItemRequest originalInput, UpdateItemResponse sdkOutput) {
        TableConfig table = tableConfigs.get(originalInput.tableName());
        if (table == null || !sdkOutput.hasAttributes() || sdkOutput.attributes().isEmpty()) {
            return sdkOutput;
        }
        ReturnValue returnValues = originalInput.returnValues();
        boolean wholeItem = returnValues == ReturnValue.ALL_OLD || returnValues == ReturnValue.ALL_NEW;
        if (!wholeItem) {
            // A partial item (UPDATED_OLD/UPDATED_NEW, or unset) cannot be
            // verified; a returned signed attribute is a hard error.
            for (String name : sdkOutput.attributes().keySet()) {
                if (isSigned(table, name)) {
                    throw new DynamoDbEncryptionTransformsException(
                        "UpdateItem response contains signed attributes, but does not include the "
                            + "entire item which is required for verification.");
                }
            }
            return sdkOutput;
        }
        Map<String, AttributeValue> plaintext =
            removeBeacons(table, table.itemCryptor().decryptItem(sdkOutput.attributes()));
        return sdkOutput.toBuilder().attributes(plaintext).build();
    }

    // --- BatchWriteItem --------------------------------------------------

    public BatchWriteItemRequest batchWriteItemInputTransform(BatchWriteItemRequest sdkInput) {
        Map<String, List<WriteRequest>> result = new LinkedHashMap<>();
        sdkInput.requestItems().forEach((tableName, writeRequests) -> {
            if (isPlainWrite(tableName)) {
                result.put(tableName, writeRequests);
                return;
            }
            TableConfig table = tableConfigs.get(tableName);
            List<WriteRequest> encrypted = new ArrayList<>(writeRequests.size());
            for (WriteRequest request : writeRequests) {
                if (request.putRequest() == null) {
                    encrypted.add(request);
                } else {
                    Map<String, AttributeValue> item = encryptForWrite(table, request.putRequest().item());
                    encrypted.add(request.toBuilder()
                        .putRequest(PutRequest.builder().item(item).build())
                        .build());
                }
            }
            result.put(tableName, encrypted);
        });
        return sdkInput.toBuilder().requestItems(result).build();
    }

    public BatchWriteItemResponse batchWriteItemOutputTransform(
            BatchWriteItemRequest originalInput, BatchWriteItemResponse sdkOutput) {
        if (!sdkOutput.hasUnprocessedItems() || sdkOutput.unprocessedItems().isEmpty()) {
            return sdkOutput;
        }
        Map<String, List<WriteRequest>> result = new LinkedHashMap<>();
        sdkOutput.unprocessedItems().forEach((tableName, writeRequests) -> {
            if (isPlainWrite(tableName)) {
                result.put(tableName, writeRequests);
                return;
            }
            List<WriteRequest> sourceRequests = originalInput.requestItems().get(tableName);
            if (sourceRequests == null) {
                throw new DynamoDbEncryptionTransformsException(tableName
                    + " in UnprocessedItems for BatchWriteItem response, but not in original request.");
            }
            TableConfig table = tableConfigs.get(tableName);
            List<WriteRequest> restored = new ArrayList<>(writeRequests.size());
            for (WriteRequest request : writeRequests) {
                if (request.putRequest() == null) {
                    restored.add(request);
                } else {
                    restored.add(originalWriteRequest(table, sourceRequests, request.putRequest().item()));
                }
            }
            result.put(tableName, restored);
        });
        return sdkOutput.toBuilder().unprocessedItems(result).build();
    }

    // --- TransactWriteItems ----------------------------------------------

    public TransactWriteItemsRequest transactWriteItemsInputTransform(TransactWriteItemsRequest sdkInput) {
        List<TransactWriteItem> result = new ArrayList<>(sdkInput.transactItems().size());
        for (TransactWriteItem item : sdkInput.transactItems()) {
            if (item.put() == null && item.update() == null
                    && item.delete() == null && item.conditionCheck() == null) {
                throw new DynamoDbEncryptionTransformsException(
                    "Each item in TransactWriteItems must specify at least one supported operation.");
            }
            ConditionCheck conditionCheck = item.conditionCheck();
            if (conditionCheck != null && tableConfigs.containsKey(conditionCheck.tableName())) {
                testConditionExpression(tableConfigs.get(conditionCheck.tableName()),
                    conditionCheck.conditionExpression(), conditionCheck.expressionAttributeNames());
            }
            Delete delete = item.delete();
            if (delete != null && tableConfigs.containsKey(delete.tableName())) {
                testConditionExpression(tableConfigs.get(delete.tableName()),
                    delete.conditionExpression(), delete.expressionAttributeNames());
            }
            Update update = item.update();
            if (update != null && tableConfigs.containsKey(update.tableName())) {
                TableConfig table = tableConfigs.get(update.tableName());
                testUpdateExpression(table, update.updateExpression(), update.expressionAttributeNames());
                testConditionExpression(table, update.conditionExpression(), update.expressionAttributeNames());
            }
            Put put = item.put();
            if (put != null && !isPlainWrite(put.tableName())) {
                TableConfig table = tableConfigs.get(put.tableName());
                testConditionExpression(table, put.conditionExpression(), put.expressionAttributeNames());
                Map<String, AttributeValue> encrypted = encryptForWrite(table, put.item());
                result.add(item.toBuilder().put(put.toBuilder().item(encrypted).build()).build());
            } else {
                result.add(item);
            }
        }
        return sdkInput.toBuilder().transactItems(result).build();
    }

    public TransactWriteItemsResponse transactWriteItemsOutputTransform(
            TransactWriteItemsRequest originalInput, TransactWriteItemsResponse sdkOutput) {
        return sdkOutput;
    }

    // --- Query / Scan ----------------------------------------------------

    public QueryRequest queryInputTransform(QueryRequest sdkInput) {
        if (!tableConfigs.containsKey(sdkInput.tableName())) {
            return sdkInput;
        }
        rejectLegacyReadParameters(
            sdkInput.hasAttributesToGet(), sdkInput.hasKeyConditions(),
            sdkInput.hasQueryFilter(), sdkInput.conditionalOperator() != null);
        Optional<SearchInfo> search = tableConfigs.get(sdkInput.tableName()).search();
        if (search.isEmpty()) {
            return sdkInput;
        }
        ExprContext context = new ExprContext(
            sdkInput.keyConditionExpression(),
            sdkInput.filterExpression(),
            sdkInput.hasExpressionAttributeValues() ? sdkInput.expressionAttributeValues() : null,
            sdkInput.hasExpressionAttributeNames() ? sdkInput.expressionAttributeNames() : null);
        ExprContext rewritten = search.get().beaconizeQuery(context);
        return sdkInput.toBuilder()
            .keyConditionExpression(rewritten.keyExpr())
            .filterExpression(rewritten.filterExpr())
            .expressionAttributeNames(rewritten.names())
            .expressionAttributeValues(rewritten.values())
            .build();
    }

    public QueryResponse queryOutputTransform(QueryRequest originalInput, QueryResponse sdkOutput) {
        TableConfig table = tableConfigs.get(originalInput.tableName());
        if (table == null || !sdkOutput.hasItems() || sdkOutput.items().isEmpty()) {
            return sdkOutput;
        }
        Optional<SearchInfo> search = table.search();
        if (search.isEmpty()) {
            return sdkOutput.toBuilder().items(decryptItems(table, sdkOutput.items())).build();
        }
        ExprContext context = new ExprContext(
            originalInput.keyConditionExpression(),
            originalInput.filterExpression(),
            originalInput.hasExpressionAttributeValues() ? originalInput.expressionAttributeValues() : null,
            originalInput.hasExpressionAttributeNames() ? originalInput.expressionAttributeNames() : null);
        List<Map<String, AttributeValue>> items = filterAndStrip(table, search.get(), sdkOutput.items(), context);
        QueryResponse.Builder builder = sdkOutput.toBuilder().items(items);
        if (sdkOutput.count() != null) {
            builder.count(items.size());
        }
        return builder.build();
    }

    public ScanRequest scanInputTransform(ScanRequest sdkInput) {
        if (!tableConfigs.containsKey(sdkInput.tableName())) {
            return sdkInput;
        }
        rejectLegacyReadParameters(
            sdkInput.hasAttributesToGet(), sdkInput.hasScanFilter(),
            false, sdkInput.conditionalOperator() != null);
        Optional<SearchInfo> search = tableConfigs.get(sdkInput.tableName()).search();
        if (search.isEmpty()) {
            return sdkInput;
        }
        ExprContext context = new ExprContext(
            null,
            sdkInput.filterExpression(),
            sdkInput.hasExpressionAttributeValues() ? sdkInput.expressionAttributeValues() : null,
            sdkInput.hasExpressionAttributeNames() ? sdkInput.expressionAttributeNames() : null);
        ExprContext rewritten = search.get().beaconizeQuery(context);
        return sdkInput.toBuilder()
            .filterExpression(rewritten.filterExpr())
            .expressionAttributeNames(rewritten.names())
            .expressionAttributeValues(rewritten.values())
            .build();
    }

    public ScanResponse scanOutputTransform(ScanRequest originalInput, ScanResponse sdkOutput) {
        TableConfig table = tableConfigs.get(originalInput.tableName());
        if (table == null || !sdkOutput.hasItems() || sdkOutput.items().isEmpty()) {
            return sdkOutput;
        }
        Optional<SearchInfo> search = table.search();
        if (search.isEmpty()) {
            return sdkOutput.toBuilder().items(decryptItems(table, sdkOutput.items())).build();
        }
        ExprContext context = new ExprContext(
            null,
            originalInput.filterExpression(),
            originalInput.hasExpressionAttributeValues() ? originalInput.expressionAttributeValues() : null,
            originalInput.hasExpressionAttributeNames() ? originalInput.expressionAttributeNames() : null);
        List<Map<String, AttributeValue>> items = filterAndStrip(table, search.get(), sdkOutput.items(), context);
        ScanResponse.Builder builder = sdkOutput.toBuilder().items(items);
        if (sdkOutput.count() != null) {
            builder.count(items.size());
        }
        return builder.build();
    }

    // --- PartiQL (unsupported on encrypted tables) -----------------------

    public ExecuteStatementRequest executeStatementInputTransform(ExecuteStatementRequest sdkInput) {
        rejectEncryptedTableStatement(sdkInput.statement());
        return sdkInput;
    }

    public ExecuteStatementResponse executeStatementOutputTransform(
            ExecuteStatementRequest originalInput, ExecuteStatementResponse sdkOutput) {
        return sdkOutput;
    }

    public BatchExecuteStatementRequest batchExecuteStatementInputTransform(
            BatchExecuteStatementRequest sdkInput) {
        for (BatchStatementRequest request : sdkInput.statements()) {
            rejectEncryptedTableStatement(request.statement());
        }
        return sdkInput;
    }

    public BatchExecuteStatementResponse batchExecuteStatementOutputTransform(
            BatchExecuteStatementRequest originalInput, BatchExecuteStatementResponse sdkOutput) {
        return sdkOutput;
    }

    public ExecuteTransactionRequest executeTransactionInputTransform(ExecuteTransactionRequest sdkInput) {
        for (ParameterizedStatement statement : sdkInput.transactStatements()) {
            rejectEncryptedTableStatement(statement.statement());
        }
        return sdkInput;
    }

    public ExecuteTransactionResponse executeTransactionOutputTransform(
            ExecuteTransactionRequest originalInput, ExecuteTransactionResponse sdkOutput) {
        return sdkOutput;
    }

    // PartiQL is unsupported on encrypted tables. An unparseable table name is a
    // hard failure (never passed through), matching the Dafny :- propagation.
    private void rejectEncryptedTableStatement(String statement) {
        String tableName = PartiqlStatement.tableFromStatement(statement);
        if (tableName == null) {
            throw new DynamoDbEncryptionTransformsException(
                "Unable to extract table name from PartiQL statement.");
        }
        if (tableConfigs.containsKey(tableName)) {
            throw new DynamoDbEncryptionTransformsException(
                "PartiQL statements are not supported on encrypted tables.");
        }
    }

    // --- shared helpers --------------------------------------------------

    private boolean isPlainWrite(String tableName) {
        TableConfig table = tableConfigs.get(tableName);
        return table == null
            || table.plaintextOverride() == PlaintextOverride.FORCE_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ;
    }

    private static void rejectLegacyWriteParameters(boolean hasExpected, boolean hasConditionalOperator) {
        if (hasExpected) {
            throw new DynamoDbEncryptionTransformsException(
                "Legacy parameter 'Expected' not supported with Encryption.");
        }
        if (hasConditionalOperator) {
            throw new DynamoDbEncryptionTransformsException(
                "Legacy parameter 'ConditionalOperator' not supported with Encryption.");
        }
    }

    // Fails if the condition expression references an encrypted attribute, per
    // Dafny TestConditionExpression. A null expression trivially passes.
    private void testConditionExpression(TableConfig table, String expr, Map<String, String> names) {
        if (expr == null) {
            return;
        }
        List<String> encrypted = new ArrayList<>();
        for (String attr : ConditionExpressionParser.extractAttributes(expr, names)) {
            if (isEncrypted(table, attr)) {
                encrypted.add(attr);
            }
        }
        if (!encrypted.isEmpty()) {
            throw new DynamoDbEncryptionTransformsException(
                "Condition Expressions forbidden on encrypted attributes : " + String.join(",", encrypted));
        }
    }

    // Fails if the update expression references a signed attribute, per Dafny
    // TestUpdateExpression. A null expression trivially passes.
    private void testUpdateExpression(TableConfig table, String expr, Map<String, String> names) {
        if (expr == null) {
            return;
        }
        List<String> signed = new ArrayList<>();
        for (String attr : UpdateExpressionParser.extractAttributes(expr, names)) {
            if (isSigned(table, attr)) {
                signed.add(attr);
            }
        }
        if (!signed.isEmpty()) {
            throw new DynamoDbEncryptionTransformsException(
                "Update Expressions forbidden on signed attributes : " + String.join(",", signed));
        }
    }

    private static boolean isEncrypted(TableConfig table, String attr) {
        return table.attributeActionsOnEncrypt().get(attr) == CryptoAction.ENCRYPT_AND_SIGN;
    }

    private static boolean isSigned(TableConfig table, String attr) {
        CryptoAction action = table.attributeActionsOnEncrypt().get(attr);
        return action != null && action != CryptoAction.DO_NOTHING;
    }

    // Rejects an item unsuitable for writing: no attribute name may begin with
    // the reserved "aws_dbe_" prefix.
    private static void requireWriteable(Map<String, AttributeValue> item) {
        for (String name : item.keySet()) {
            if (name.startsWith(BEACON_PREFIX)) {
                throw new DynamoDbEncryptionTransformsException(
                    "Attribute name " + name + " not allowed; names starting with \"aws_dbe_\" are reserved.");
            }
        }
    }

    // Encrypt a plaintext item for a write: reject reserved names, add signed
    // beacons (no-op), encrypt, then append encrypted beacons (empty).
    private Map<String, AttributeValue> encryptForWrite(TableConfig table, Map<String, AttributeValue> item) {
        requireWriteable(item);
        Map<String, AttributeValue> signed = addSignedBeacons(table, item);
        Map<String, AttributeValue> encrypted = table.itemCryptor().encryptItem(signed);
        return merge(encrypted, encryptedBeacons(table, item));
    }

    private List<Map<String, AttributeValue>> decryptItems(
            TableConfig table, List<Map<String, AttributeValue>> items) {
        List<Map<String, AttributeValue>> decrypted = new ArrayList<>(items.size());
        for (Map<String, AttributeValue> item : items) {
            decrypted.add(removeBeacons(table, table.itemCryptor().decryptItem(item)));
        }
        return decrypted;
    }

    // The search-path Query/Scan output (DDBSupport QueryOutputForBeacons): decrypt each item
    // keeping its beacons, re-filter the decrypted superset against the original expressions,
    // then strip beacons from the survivors. The caller updates the response Count.
    private List<Map<String, AttributeValue>> filterAndStrip(
            TableConfig table, SearchInfo search,
            List<Map<String, AttributeValue>> encrypted, ExprContext originalContext) {
        List<Map<String, AttributeValue>> decrypted = new ArrayList<>(encrypted.size());
        for (Map<String, AttributeValue> item : encrypted) {
            decrypted.add(table.itemCryptor().decryptItem(item));
        }
        List<Map<String, AttributeValue>> filtered = search.filterResults(originalContext, decrypted);
        List<Map<String, AttributeValue>> trimmed = new ArrayList<>(filtered.size());
        for (Map<String, AttributeValue> item : filtered) {
            trimmed.add(removeBeacons(table, item));
        }
        return trimmed;
    }

    private static void rejectLegacyReadParameters(
            boolean hasAttributesToGet, boolean hasConditions,
            boolean hasFilter, boolean hasConditionalOperator) {
        if (hasAttributesToGet) {
            throw new DynamoDbEncryptionTransformsException(
                "Legacy parameter 'AttributesToGet' not supported with Encryption.");
        }
        if (hasConditions) {
            throw new DynamoDbEncryptionTransformsException(
                "Legacy KeyConditions/ScanFilter parameter not supported with Encryption.");
        }
        if (hasFilter) {
            throw new DynamoDbEncryptionTransformsException(
                "Legacy parameter 'QueryFilter' not supported with Encryption.");
        }
        if (hasConditionalOperator) {
            throw new DynamoDbEncryptionTransformsException(
                "Legacy parameter 'ConditionalOperator' not supported with Encryption.");
        }
    }

    // Finds the original (plaintext) request matching an unprocessed put by
    // partition (and sort) key, so an unprocessed put is restored to plaintext.
    private static WriteRequest originalWriteRequest(
            TableConfig table, List<WriteRequest> sourceRequests, Map<String, AttributeValue> unprocessedItem) {
        String partitionKey = table.partitionKeyName();
        AttributeValue partitionValue = unprocessedItem.get(partitionKey);
        if (partitionValue == null) {
            throw new DynamoDbEncryptionTransformsException("Required partition key not in unprocessed item.");
        }
        Optional<String> sortKey = table.sortKeyName();
        for (WriteRequest candidate : sourceRequests) {
            if (candidate.putRequest() == null) {
                continue;
            }
            Map<String, AttributeValue> item = candidate.putRequest().item();
            boolean partitionMatches = partitionValue.equals(item.get(partitionKey));
            boolean sortMatches = sortKey.isEmpty()
                || (unprocessedItem.get(sortKey.get()) != null
                    && unprocessedItem.get(sortKey.get()).equals(item.get(sortKey.get())));
            if (partitionMatches && sortMatches) {
                return candidate;
            }
        }
        throw new DynamoDbEncryptionTransformsException(
            "Item in UnprocessedItems not found in original request.");
    }

    // Beacon write-path seams: a table without a search config is a no-op; a
    // configured table runs the native beacon layer.
    private static Map<String, AttributeValue> addSignedBeacons(TableConfig table, Map<String, AttributeValue> item) {
        return table.search().map(search -> search.addSignedBeacons(item)).orElse(item);
    }

    private static Map<String, AttributeValue> encryptedBeacons(TableConfig table, Map<String, AttributeValue> item) {
        return table.search().map(search -> search.encryptedBeacons(item)).orElse(Map.of());
    }

    // Strips every attribute whose name begins with the reserved "aws_dbe_"
    // prefix, leaving the rest unchanged (Dafny RemoveBeacons/DoRemoveBeacons).
    // Search-independent: a decrypted item still carries any stored beacon
    // attributes, which the caller must not see.
    private static Map<String, AttributeValue> removeBeacons(TableConfig table, Map<String, AttributeValue> item) {
        Map<String, AttributeValue> out = new LinkedHashMap<>();
        for (Map.Entry<String, AttributeValue> entry : item.entrySet()) {
            if (!entry.getKey().startsWith(BEACON_PREFIX)) {
                out.put(entry.getKey(), entry.getValue());
            }
        }
        return out;
    }

    private static Map<String, AttributeValue> merge(
            Map<String, AttributeValue> base, Map<String, AttributeValue> additions) {
        if (additions.isEmpty()) {
            return base;
        }
        Map<String, AttributeValue> merged = new LinkedHashMap<>(base);
        merged.putAll(additions);
        return merged;
    }
}
