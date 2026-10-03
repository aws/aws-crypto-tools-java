package software.amazon.cryptography.dbesdk.dynamodbitemencryptor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbesdk.dynamodbencryption.DynamoToStruct;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthenticateAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Terminal;

class ItemEncryptorCoreTest {

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static Map<String, Terminal> structured(Map<String, AttributeValue> item) {
        Map<String, Terminal> out = new LinkedHashMap<>();
        item.forEach((k, v) -> out.put(k, DynamoToStruct.attrToStructured(v)));
        return out;
    }

    @Test
    void versionDerivedFromActions() {
        ItemEncryptorConfig v1 = ItemEncryptorConfig.builder()
            .logicalTableName("T").partitionKeyName("pk")
            .attributeActionsOnEncrypt(Map.of("pk", CryptoAction.SIGN_ONLY, "x", CryptoAction.ENCRYPT_AND_SIGN))
            .build();
        assertEquals(1, v1.version());

        ItemEncryptorConfig v2 = ItemEncryptorConfig.builder()
            .logicalTableName("T").partitionKeyName("pk")
            .attributeActionsOnEncrypt(Map.of("pk", CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT))
            .build();
        assertEquals(2, v2.version());
    }

    @Test
    void rejectsWrongPartitionKeyAction() {
        DynamoDbItemEncryptorException thrown = assertThrows(
            DynamoDbItemEncryptorException.class,
            () -> ItemEncryptorConfig.builder()
                .logicalTableName("T").partitionKeyName("pk")
                .attributeActionsOnEncrypt(Map.of("pk", CryptoAction.ENCRYPT_AND_SIGN))
                .build());
        assertEquals("Partition key attribute action MUST be SIGN_ONLY", thrown.getMessage());
    }

    @Test
    void rejectsReservedAttributeName() {
        // DO_NOTHING on a reserved-prefix attribute passes the forward-compatibility
        // check (it is allowed-unsigned), so validation reaches the reserved-name check.
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put("pk", CryptoAction.SIGN_ONLY);
        actions.put("aws_dbe_x", CryptoAction.DO_NOTHING);
        DynamoDbItemEncryptorException thrown = assertThrows(
            DynamoDbItemEncryptorException.class,
            () -> ItemEncryptorConfig.builder()
                .logicalTableName("T").partitionKeyName("pk").attributeActionsOnEncrypt(actions).build());
        assertEquals("Attribute: aws_dbe_x is reserved, and may not be configured.", thrown.getMessage());
    }

    @Test
    void rejectsDoNothingNotAllowedUnsigned() {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put("pk", CryptoAction.SIGN_ONLY);
        actions.put("d", CryptoAction.DO_NOTHING);
        DynamoDbItemEncryptorException thrown = assertThrows(
            DynamoDbItemEncryptorException.class,
            () -> ItemEncryptorConfig.builder()
                .logicalTableName("T").partitionKeyName("pk").attributeActionsOnEncrypt(actions).build());
        assertEquals(
            "Attribute d is configured as DO_NOTHING but it must also be in unauthenticatedAttributes"
                + " or begin with the unauthenticatedPrefix.",
            thrown.getMessage());
    }

    @Test
    void rejectsSignedAttributeThatIsAllowedUnsigned() {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put("pk", CryptoAction.SIGN_ONLY);
        actions.put("s", CryptoAction.SIGN_ONLY);
        DynamoDbItemEncryptorException thrown = assertThrows(
            DynamoDbItemEncryptorException.class,
            () -> ItemEncryptorConfig.builder()
                .logicalTableName("T").partitionKeyName("pk")
                .attributeActionsOnEncrypt(actions).allowedUnsignedAttributes(Set.of("s")).build());
        assertEquals(
            "Attribute s is configured as SIGN_ONLY but it is also in unauthenticatedAttributes.",
            thrown.getMessage());
    }

    @Test
    void encryptionContextV1CarriesEncodedKeyValues() {
        ItemEncryptorConfig config = ItemEncryptorConfig.builder()
            .logicalTableName("MyTable").partitionKeyName("pk").sortKeyName("sk")
            .attributeActionsOnEncrypt(Map.of("pk", CryptoAction.SIGN_ONLY, "sk", CryptoAction.SIGN_ONLY))
            .build();
        Map<String, AttributeValue> item = new LinkedHashMap<>();
        item.put("pk", AttributeValue.fromS("a"));
        item.put("sk", AttributeValue.fromN("5"));

        Map<String, byte[]> context =
            ItemEncryptorOperations.makeEncryptionContextForEncrypt(config, structured(item));

        Map<String, byte[]> expected = new LinkedHashMap<>();
        expected.put("aws-crypto-table-name", ascii("MyTable"));
        expected.put("aws-crypto-partition-name", ascii("pk"));
        expected.put("aws-crypto-attr.pk", ascii("AAFh")); // base64(00 01 'a')
        expected.put("aws-crypto-sort-name", ascii("sk"));
        expected.put("aws-crypto-attr.sk", ascii("AAI1")); // base64(00 02 '5')
        assertContext(expected, context);
    }

    @Test
    void encryptionContextV2CarriesOnlyNames() {
        ItemEncryptorConfig config = ItemEncryptorConfig.builder()
            .logicalTableName("T").partitionKeyName("pk")
            .attributeActionsOnEncrypt(Map.of("pk", CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT))
            .build();
        Map<String, AttributeValue> item = Map.of("pk", AttributeValue.fromS("a"));

        Map<String, byte[]> context =
            ItemEncryptorOperations.makeEncryptionContextForEncrypt(config, structured(item));

        Map<String, byte[]> expected = new LinkedHashMap<>();
        expected.put("aws-crypto-table-name", ascii("T"));
        expected.put("aws-crypto-partition-name", ascii("pk"));
        assertContext(expected, context);
    }

    @Test
    void decryptContextSelectedByHeaderVersion() {
        ItemEncryptorConfig config = ItemEncryptorConfig.builder()
            .logicalTableName("T").partitionKeyName("pk")
            .attributeActionsOnEncrypt(Map.of("pk", CryptoAction.SIGN_ONLY))
            .build();
        Map<String, Terminal> item = structured(Map.of("pk", AttributeValue.fromS("a")));

        // V1 carries the key value, V2 does not.
        assertTrue(ItemEncryptorOperations.makeEncryptionContextForDecrypt(config, 1, item)
            .containsKey("aws-crypto-attr.pk"));
        assertFalse(ItemEncryptorOperations.makeEncryptionContextForDecrypt(config, 2, item)
            .containsKey("aws-crypto-attr.pk"));

        DynamoDbItemEncryptorException thrown = assertThrows(
            DynamoDbItemEncryptorException.class,
            () -> ItemEncryptorOperations.makeEncryptionContextForDecrypt(config, 3, item));
        assertEquals("Header attribute has unexpected version number", thrown.getMessage());
    }

    @Test
    void cryptoSchemaMapsActionsAndRejectsUnconfiguredInScope() {
        ItemEncryptorConfig config = ItemEncryptorConfig.builder()
            .logicalTableName("T").partitionKeyName("pk")
            .attributeActionsOnEncrypt(Map.of("pk", CryptoAction.SIGN_ONLY, "enc", CryptoAction.ENCRYPT_AND_SIGN))
            .allowedUnsignedAttributes(Set.of("plain"))
            .build();

        Map<String, CryptoAction> schema =
            ItemEncryptorOperations.configToCryptoSchema(config, Set.of("pk", "enc", "plain"));
        assertEquals(CryptoAction.SIGN_ONLY, schema.get("pk"));
        assertEquals(CryptoAction.ENCRYPT_AND_SIGN, schema.get("enc"));
        assertEquals(CryptoAction.DO_NOTHING, schema.get("plain")); // out of scope, unconfigured

        DynamoDbItemEncryptorException thrown = assertThrows(
            DynamoDbItemEncryptorException.class,
            () -> ItemEncryptorOperations.configToCryptoSchema(config, Set.of("surprise")));
        assertEquals("No Crypto Action configured for attribute surprise", thrown.getMessage());
    }

    @Test
    void authenticateSchemaFollowsSignatureScope() {
        ItemEncryptorConfig config = ItemEncryptorConfig.builder()
            .logicalTableName("T").partitionKeyName("pk")
            .attributeActionsOnEncrypt(Map.of("pk", CryptoAction.SIGN_ONLY))
            .allowedUnsignedAttributes(Set.of("plain"))
            .allowedUnsignedAttributePrefix(":")
            .build();

        Map<String, AuthenticateAction> schema = ItemEncryptorOperations.configToAuthenticateSchema(
            config, Set.of("pk", "plain", ":skip", "aws_dbe_head"));
        assertEquals(AuthenticateAction.SIGN, schema.get("pk"));
        assertEquals(AuthenticateAction.DO_NOT_SIGN, schema.get("plain")); // allowed-unsigned
        assertEquals(AuthenticateAction.DO_NOT_SIGN, schema.get(":skip")); // unsigned prefix
        assertEquals(AuthenticateAction.DO_NOT_SIGN, schema.get("aws_dbe_head")); // reserved prefix
    }

    @Test
    void isPlaintextItemChecksHeaderAndFooter() {
        assertTrue(ItemEncryptorOperations.isPlaintextItem(Map.of("pk", AttributeValue.fromS("a"))));
        assertFalse(ItemEncryptorOperations.isPlaintextItem(
            Map.of("pk", AttributeValue.fromS("a"), "aws_dbe_head", AttributeValue.fromS("h"))));
    }

    private static void assertContext(Map<String, byte[]> expected, Map<String, byte[]> actual) {
        assertEquals(expected.keySet(), actual.keySet());
        expected.forEach((key, value) -> assertArrayEquals(value, actual.get(key), key));
    }
}
