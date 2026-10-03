package software.amazon.cryptography.dbesdk.dynamodbencryption;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Terminal;

class DynamoToStructItemLayerTest {

    private static AttributeValue bin(int... values) {
        byte[] out = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            out[i] = (byte) values[i];
        }
        return AttributeValue.fromB(SdkBytes.fromByteArray(out));
    }

    @Test
    void itemToStructuredOmitsUnsignedDoNothingButKeepsReserved() {
        Map<String, AttributeValue> item = new LinkedHashMap<>();
        item.put("enc", AttributeValue.fromS("secret"));
        item.put("plain", AttributeValue.fromN("5"));
        item.put("skip", AttributeValue.fromS("ignored"));
        item.put("aws_dbe_head", bin(9));
        Map<String, CryptoAction> actions = Map.of(
            "enc", CryptoAction.ENCRYPT_AND_SIGN,
            "plain", CryptoAction.SIGN_ONLY,
            "skip", CryptoAction.DO_NOTHING);
        // aws_dbe_head is absent from actions but kept because it is reserved-prefix.

        Map<String, Terminal> structured = DynamoToStruct.itemToStructured(item, actions);

        assertEquals(Set.of("enc", "plain", "aws_dbe_head"), structured.keySet());
        assertEquals(AttributeValue.fromS("secret"), DynamoToStruct.structuredToAttr(structured.get("enc")));
        assertEquals(AttributeValue.fromN("5"), DynamoToStruct.structuredToAttr(structured.get("plain")));
    }

    @Test
    void structuredToItemEncryptReplacesEncryptedPassesThroughOthersAndAddsReserved() {
        Map<String, AttributeValue> orig = new LinkedHashMap<>();
        orig.put("enc", AttributeValue.fromS("secret"));
        orig.put("sign", AttributeValue.fromN("7"));
        orig.put("plain", AttributeValue.fromS("keep"));
        Map<String, CryptoAction> actions = Map.of(
            "enc", CryptoAction.ENCRYPT_AND_SIGN,
            "sign", CryptoAction.SIGN_ONLY,
            "plain", CryptoAction.DO_NOTHING);

        Map<String, Terminal> s = new LinkedHashMap<>();
        s.put("enc", DynamoToStruct.attrToStructured(bin(1, 2, 3))); // stands in for ciphertext
        s.put("sign", DynamoToStruct.attrToStructured(AttributeValue.fromN("7")));
        s.put("aws_dbe_head", DynamoToStruct.attrToStructured(bin(9, 9))); // added by SE, not in orig

        Map<String, AttributeValue> item = DynamoToStruct.structuredToItemEncrypt(s, orig, actions);

        assertEquals(Set.of("enc", "sign", "plain", "aws_dbe_head"), item.keySet());
        assertEquals(bin(1, 2, 3), item.get("enc")); // ENCRYPT_AND_SIGN -> re-serialized structured value
        assertEquals(AttributeValue.fromN("7"), item.get("sign")); // signed -> original passthrough
        assertEquals(AttributeValue.fromS("keep"), item.get("plain")); // DO_NOTHING -> original passthrough
        assertEquals(bin(9, 9), item.get("aws_dbe_head")); // reserved, added from structured map
    }

    @Test
    void structuredToItemDecryptDecryptsPassesThroughAndDropsReserved() {
        Map<String, AttributeValue> orig = new LinkedHashMap<>();
        orig.put("enc", bin(1, 2, 3)); // stored ciphertext
        orig.put("sign", AttributeValue.fromN("7"));
        orig.put("plain", AttributeValue.fromS("keep"));
        orig.put("aws_dbe_head", bin(9));
        orig.put("aws_dbe_foot", bin(8));
        Map<String, CryptoAction> actions = Map.of(
            "enc", CryptoAction.ENCRYPT_AND_SIGN,
            "sign", CryptoAction.SIGN_ONLY,
            "plain", CryptoAction.DO_NOTHING);

        Map<String, Terminal> s = new LinkedHashMap<>();
        s.put("enc", DynamoToStruct.attrToStructured(AttributeValue.fromS("secret"))); // decrypted value
        s.put("sign", DynamoToStruct.attrToStructured(AttributeValue.fromN("7")));

        Map<String, AttributeValue> item = DynamoToStruct.structuredToItemDecrypt(s, orig, actions);

        assertEquals(Set.of("enc", "sign", "plain"), item.keySet());
        assertEquals(AttributeValue.fromS("secret"), item.get("enc")); // decrypted from structured map
        assertEquals(AttributeValue.fromN("7"), item.get("sign")); // signed -> original passthrough
        assertEquals(AttributeValue.fromS("keep"), item.get("plain")); // DO_NOTHING -> original passthrough
        assertFalse(item.containsKey("aws_dbe_head")); // reserved header dropped
        assertFalse(item.containsKey("aws_dbe_foot")); // reserved footer dropped
    }
}
