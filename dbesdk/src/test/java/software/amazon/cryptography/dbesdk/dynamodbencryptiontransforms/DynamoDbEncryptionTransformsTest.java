package software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbesdk.dynamodbencryption.BeaconVersion;
import software.amazon.cryptography.dbesdk.dynamodbencryption.LiteralBeaconKeySource;
import software.amazon.cryptography.dbesdk.dynamodbencryption.StandardBeacon;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ExecuteStatementRequest;
import software.amazon.awssdk.services.dynamodb.model.Get;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.ItemResponse;
import software.amazon.awssdk.services.dynamodb.model.Put;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryResponse;
import software.amazon.awssdk.services.dynamodb.model.ReturnValue;
import software.amazon.awssdk.services.dynamodb.model.TransactGetItem;
import software.amazon.awssdk.services.dynamodb.model.TransactGetItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactGetItemsResponse;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemResponse;
import software.amazon.awssdk.services.dynamodb.model.WriteRequest;
import software.amazon.cryptography.dbesdk.dynamodbitemencryptor.PlaintextOverride;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction;

class DynamoDbEncryptionTransformsTest {

    private static final String TABLE = "encrypted_table";
    private static final String MARKER = "ENCRYPTED";

    // Reversible fake: encrypt stamps a marker attribute, decrypt removes it, so a
    // test can tell whether the middleware ran encrypt/decrypt without any MPL.
    private static final class MarkerCryptor implements ItemCryptor {
        @Override
        public Map<String, AttributeValue> encryptItem(Map<String, AttributeValue> item) {
            Map<String, AttributeValue> out = new LinkedHashMap<>(item);
            out.put(MARKER, AttributeValue.fromS("1"));
            return out;
        }

        @Override
        public Map<String, AttributeValue> decryptItem(Map<String, AttributeValue> item) {
            Map<String, AttributeValue> out = new LinkedHashMap<>(item);
            out.remove(MARKER);
            return out;
        }
    }

    private static DynamoDbEncryptionTransforms client(PlaintextOverride override) {
        return clientWithActions(override, Map.of());
    }

    private static DynamoDbEncryptionTransforms clientWithActions(
            PlaintextOverride override, Map<String, CryptoAction> actions) {
        TableConfig table = TableConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName("pk")
            .plaintextOverride(override)
            .attributeActionsOnEncrypt(actions)
            .itemCryptor(new MarkerCryptor())
            .build();
        return new DynamoDbEncryptionTransforms(Map.of(TABLE, table));
    }

    private static DynamoDbEncryptionTransforms client() {
        return client(PlaintextOverride.FORBID_PLAINTEXT_WRITE_FORBID_PLAINTEXT_READ);
    }

    @Test
    void putInputPassesThroughUnconfiguredTable() {
        PutItemRequest input = PutItemRequest.builder()
            .tableName("other_table")
            .item(Map.of("a", AttributeValue.fromS("x")))
            .build();
        assertSame(input, client().putItemInputTransform(input));
    }

    @Test
    void putInputEncryptsItem() {
        PutItemRequest input = PutItemRequest.builder()
            .tableName(TABLE)
            .item(Map.of("a", AttributeValue.fromS("x")))
            .build();
        PutItemRequest out = client().putItemInputTransform(input);
        assertTrue(out.item().containsKey(MARKER));
    }

    @Test
    void putInputForcePlaintextWriteSkipsEncryption() {
        PutItemRequest input = PutItemRequest.builder()
            .tableName(TABLE)
            .item(Map.of("a", AttributeValue.fromS("x")))
            .build();
        PutItemRequest out =
            client(PlaintextOverride.FORCE_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ).putItemInputTransform(input);
        assertFalse(out.item().containsKey(MARKER));
    }

    @Test
    void putInputRejectsReservedAttributeName() {
        PutItemRequest input = PutItemRequest.builder()
            .tableName(TABLE)
            .item(Map.of("aws_dbe_x", AttributeValue.fromS("x")))
            .build();
        assertThrows(DynamoDbEncryptionTransformsException.class,
            () -> client().putItemInputTransform(input));
    }

    @Test
    void putInputRejectsConditionOnEncryptedAttribute() {
        PutItemRequest input = PutItemRequest.builder()
            .tableName(TABLE)
            .item(Map.of("a", AttributeValue.fromS("x")))
            .conditionExpression("secret = :v")
            .build();
        DynamoDbEncryptionTransforms client = clientWithActions(
            PlaintextOverride.FORBID_PLAINTEXT_WRITE_FORBID_PLAINTEXT_READ,
            Map.of("secret", CryptoAction.ENCRYPT_AND_SIGN));
        assertThrows(DynamoDbEncryptionTransformsException.class,
            () -> client.putItemInputTransform(input));
    }

    @Test
    void putInputAllowsConditionOnPlaintextAttribute() {
        PutItemRequest input = PutItemRequest.builder()
            .tableName(TABLE)
            .item(Map.of("a", AttributeValue.fromS("x")))
            .conditionExpression("attribute_not_exists(pk)")
            .build();
        PutItemRequest out = clientWithActions(
            PlaintextOverride.FORBID_PLAINTEXT_WRITE_FORBID_PLAINTEXT_READ,
            Map.of("secret", CryptoAction.ENCRYPT_AND_SIGN)).putItemInputTransform(input);
        assertTrue(out.item().containsKey(MARKER));
    }

    @Test
    void getOutputDecryptsItem() {
        GetItemRequest original = GetItemRequest.builder().tableName(TABLE).build();
        GetItemResponse response = GetItemResponse.builder()
            .item(Map.of("a", AttributeValue.fromS("x"), MARKER, AttributeValue.fromS("1")))
            .build();
        GetItemResponse out = client().getItemOutputTransform(original, response);
        assertFalse(out.item().containsKey(MARKER));
    }

    @Test
    void getOutputPassesThroughWhenNoItem() {
        GetItemRequest original = GetItemRequest.builder().tableName(TABLE).build();
        GetItemResponse response = GetItemResponse.builder().build();
        assertSame(response, client().getItemOutputTransform(original, response));
    }

    @Test
    void batchGetOutputDecryptsConfiguredTableOnly() {
        BatchGetItemRequest original = BatchGetItemRequest.builder().build();
        BatchGetItemResponse response = BatchGetItemResponse.builder()
            .responses(Map.of(
                TABLE, List.of(Map.of("a", AttributeValue.fromS("x"), MARKER, AttributeValue.fromS("1"))),
                "plain_table", List.of(Map.of("b", AttributeValue.fromS("y")))))
            .build();
        BatchGetItemResponse out = client().batchGetItemOutputTransform(original, response);
        assertFalse(out.responses().get(TABLE).get(0).containsKey(MARKER));
    }

    @Test
    void transactGetOutputRejectsCountMismatch() {
        TransactGetItemsRequest original = TransactGetItemsRequest.builder()
            .transactItems(TransactGetItem.builder()
                .get(Get.builder().tableName(TABLE).key(Map.of("pk", AttributeValue.fromS("1"))).build())
                .build())
            .build();
        TransactGetItemsResponse response = TransactGetItemsResponse.builder()
            .responses(ItemResponse.builder().build(), ItemResponse.builder().build())
            .build();
        assertThrows(DynamoDbEncryptionTransformsException.class,
            () -> client().transactGetItemsOutputTransform(original, response));
    }

    @Test
    void updateInputRejectsSignedAttributeInExpression() {
        UpdateItemRequest input = UpdateItemRequest.builder()
            .tableName(TABLE)
            .updateExpression("SET signedAttr = :v")
            .build();
        DynamoDbEncryptionTransforms client = clientWithActions(
            PlaintextOverride.FORBID_PLAINTEXT_WRITE_FORBID_PLAINTEXT_READ,
            Map.of("signedAttr", CryptoAction.SIGN_ONLY));
        assertThrows(DynamoDbEncryptionTransformsException.class,
            () -> client.updateItemInputTransform(input));
    }

    @Test
    void updateOutputUpdatedNewRejectsSignedAttribute() {
        UpdateItemRequest original = UpdateItemRequest.builder()
            .tableName(TABLE).returnValues(ReturnValue.UPDATED_NEW).build();
        UpdateItemResponse response = UpdateItemResponse.builder()
            .attributes(Map.of("signedAttr", AttributeValue.fromS("x"))).build();
        DynamoDbEncryptionTransforms client = clientWithActions(
            PlaintextOverride.FORBID_PLAINTEXT_WRITE_FORBID_PLAINTEXT_READ,
            Map.of("signedAttr", CryptoAction.SIGN_ONLY));
        assertThrows(DynamoDbEncryptionTransformsException.class,
            () -> client.updateItemOutputTransform(original, response));
    }

    @Test
    void updateOutputAllOldDecrypts() {
        UpdateItemRequest original = UpdateItemRequest.builder()
            .tableName(TABLE).returnValues(ReturnValue.ALL_OLD).build();
        UpdateItemResponse response = UpdateItemResponse.builder()
            .attributes(Map.of("a", AttributeValue.fromS("x"), MARKER, AttributeValue.fromS("1"))).build();
        UpdateItemResponse out = client().updateItemOutputTransform(original, response);
        assertFalse(out.attributes().containsKey(MARKER));
    }

    @Test
    void batchWriteInputEncryptsPutRequests() {
        WriteRequest put = WriteRequest.builder()
            .putRequest(PutRequest.builder().item(Map.of("a", AttributeValue.fromS("x"))).build())
            .build();
        BatchWriteItemRequest input = BatchWriteItemRequest.builder()
            .requestItems(Map.of(TABLE, List.of(put)))
            .build();
        BatchWriteItemRequest out = client().batchWriteItemInputTransform(input);
        assertTrue(out.requestItems().get(TABLE).get(0).putRequest().item().containsKey(MARKER));
    }

    @Test
    void transactWriteInputRejectsItemWithNoOperation() {
        TransactWriteItemsRequest input = TransactWriteItemsRequest.builder()
            .transactItems(TransactWriteItem.builder().build())
            .build();
        assertThrows(DynamoDbEncryptionTransformsException.class,
            () -> client().transactWriteItemsInputTransform(input));
    }

    @Test
    void transactWriteInputEncryptsPut() {
        TransactWriteItem item = TransactWriteItem.builder()
            .put(Put.builder().tableName(TABLE).item(Map.of("a", AttributeValue.fromS("x"))).build())
            .build();
        TransactWriteItemsRequest input = TransactWriteItemsRequest.builder()
            .transactItems(item).build();
        TransactWriteItemsRequest out = client().transactWriteItemsInputTransform(input);
        assertTrue(out.transactItems().get(0).put().item().containsKey(MARKER));
    }

    @Test
    void queryOutputDecryptsItems() {
        QueryRequest original = QueryRequest.builder().tableName(TABLE).build();
        QueryResponse response = QueryResponse.builder()
            .items(List.of(Map.of("a", AttributeValue.fromS("x"), MARKER, AttributeValue.fromS("1"))))
            .build();
        QueryResponse out = client().queryOutputTransform(original, response);
        assertFalse(out.items().get(0).containsKey(MARKER));
    }

    @Test
    void queryInputRejectsLegacyAttributesToGet() {
        QueryRequest input = QueryRequest.builder()
            .tableName(TABLE).attributesToGet("a").build();
        assertThrows(DynamoDbEncryptionTransformsException.class,
            () -> client().queryInputTransform(input));
    }

    @Test
    void partiqlRejectsEncryptedTable() {
        ExecuteStatementRequest input = ExecuteStatementRequest.builder()
            .statement("SELECT * FROM " + TABLE).build();
        assertThrows(DynamoDbEncryptionTransformsException.class,
            () -> client().executeStatementInputTransform(input));
    }

    @Test
    void partiqlPassesThroughUnconfiguredTable() {
        ExecuteStatementRequest input = ExecuteStatementRequest.builder()
            .statement("SELECT * FROM other_table").build();
        assertSame(input, client().executeStatementInputTransform(input));
    }

    @Test
    void conditionExtractorSkipsAttributeExistsOperand() {
        List<String> attrs = ConditionExpressionParser.extractAttributes(
            "attribute_exists(#a) AND #b = :v", Map.of("#a", "aa", "#b", "bb"));
        assertEquals(List.of("bb"), attrs);
    }

    @Test
    void updateExtractorChopsToRootAndResolvesName() {
        List<String> attrs = UpdateExpressionParser.extractAttributes("SET #a.b = :v", Map.of("#a", "root"));
        assertEquals(List.of("root"), attrs);
    }

    private static DynamoDbEncryptionTransforms clientWithSearch(StandardBeacon beacon, Map<String, byte[]> keys) {
        SearchInfo search = new SearchInfo(BeaconVersion.of(List.of(beacon)), new LiteralBeaconKeySource(keys));
        TableConfig table = TableConfig.builder()
            .logicalTableName(TABLE)
            .partitionKeyName("pk")
            .plaintextOverride(PlaintextOverride.FORBID_PLAINTEXT_WRITE_FORBID_PLAINTEXT_READ)
            .attributeActionsOnEncrypt(Map.of())
            .itemCryptor(new MarkerCryptor())
            .search(search)
            .build();
        return new DynamoDbEncryptionTransforms(Map.of(TABLE, table));
    }

    @Test
    void putInputWritesBeaconAndVersionTag() {
        byte[] key = new byte[64];
        java.util.Arrays.fill(key, (byte) 7);
        StandardBeacon beacon = StandardBeacon.create("std4", 16, "std4", false, 0);
        Map<String, byte[]> keys = Map.of("std4", key);
        Map<String, AttributeValue> item = Map.of("std4", AttributeValue.fromS("alpha"));

        PutItemRequest out = clientWithSearch(beacon, keys).putItemInputTransform(
            PutItemRequest.builder().tableName(TABLE).item(item).build());

        String expected = BeaconVersion.of(List.of(beacon))
            .generateEncryptedBeacons(item, keys, 0).get("aws_dbe_b_std4").s();
        assertEquals(expected, out.item().get("aws_dbe_b_std4").s());
        assertEquals(" ", out.item().get("aws_dbe_v_1").s());
    }

    @Test
    void putInputSkipsPartOnlyBeacon() {
        byte[] key = new byte[64];
        StandardBeacon partOnly = StandardBeacon.create("po", 16, "po", false, 0, null, true);
        PutItemRequest out = clientWithSearch(partOnly, Map.of("po", key)).putItemInputTransform(
            PutItemRequest.builder()
                .tableName(TABLE).item(Map.of("po", AttributeValue.fromS("x"))).build());

        assertFalse(out.item().containsKey("aws_dbe_b_po"));
        assertTrue(out.item().containsKey("aws_dbe_v_1"));
    }

    @Test
    void getOutputStripsVersionTagAndBeacons() {
        GetItemResponse response = GetItemResponse.builder()
            .item(Map.of(
                "a", AttributeValue.fromS("x"),
                "aws_dbe_v_1", AttributeValue.fromS(" "),
                "aws_dbe_b_std4", AttributeValue.fromS("abcd"),
                MARKER, AttributeValue.fromS("1")))
            .build();
        GetItemResponse out = client().getItemOutputTransform(
            GetItemRequest.builder().tableName(TABLE).build(), response);

        assertFalse(out.item().containsKey("aws_dbe_v_1"));
        assertFalse(out.item().containsKey("aws_dbe_b_std4"));
        assertTrue(out.item().containsKey("a"));
    }
}
