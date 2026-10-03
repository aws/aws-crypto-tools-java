package software.amazon.cryptography.dbesdk.dynamodbencryption;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Terminal;

class DynamoToStructTest {

    private static SdkBytes bytes(int... values) {
        byte[] out = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            out[i] = (byte) values[i];
        }
        return SdkBytes.fromByteArray(out);
    }

    private static byte[] b(int... values) {
        byte[] out = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            out[i] = (byte) values[i];
        }
        return out;
    }

    // Each case: an attribute and its exact top-level encoding (value + typeId), from
    // test/DynamoToStruct.dfy. Asserts encode matches and decode round-trips.
    private static void assertGolden(AttributeValue attr, byte[] expectedValue, byte[] expectedTypeId) {
        Terminal terminal = DynamoToStruct.attrToStructured(attr);
        assertArrayEquals(expectedValue, terminal.value());
        assertArrayEquals(expectedTypeId, terminal.typeId());
        assertEquals(attr, DynamoToStruct.structuredToAttr(terminal));
    }

    @Test
    void scalarsMatchGoldenVectors() {
        assertGolden(AttributeValue.fromS("abc"), b(97, 98, 99), b(0, 1));
        assertGolden(AttributeValue.fromN("123"), b(49, 50, 51), b(0, 2));
        assertGolden(AttributeValue.fromB(bytes(1, 2, 3, 4, 5)), b(1, 2, 3, 4, 5), b(0xFF, 0xFF));
        assertGolden(AttributeValue.fromNul(true), b(), b(0, 0));
        assertGolden(AttributeValue.fromBool(false), b(0), b(0, 4));
        assertGolden(AttributeValue.fromBool(true), b(1), b(0, 4));
    }

    @Test
    void numberIsNormalizedOnEncode() {
        // 000123.000 normalizes to 123; decode yields the normalized N("123").
        Terminal terminal = DynamoToStruct.attrToStructured(AttributeValue.fromN("000123.000"));
        assertArrayEquals(b(49, 50, 51), terminal.value());
        assertEquals(AttributeValue.fromN("123"), DynamoToStruct.structuredToAttr(terminal));
    }

    @Test
    void setsMatchGoldenVectors() {
        assertGolden(
            AttributeValue.fromSs(List.of("abc", "de")),
            b(0, 0, 0, 2, 0, 0, 0, 3, 97, 98, 99, 0, 0, 0, 2, 100, 101),
            b(1, 1));
        assertGolden(
            AttributeValue.fromNs(List.of("123", "45")),
            b(0, 0, 0, 2, 0, 0, 0, 3, 49, 50, 51, 0, 0, 0, 2, 52, 53),
            b(1, 2));
        assertGolden(
            AttributeValue.fromBs(List.of(bytes(1, 2, 3), bytes(4, 5))),
            b(0, 0, 0, 2, 0, 0, 0, 3, 1, 2, 3, 0, 0, 0, 2, 4, 5),
            b(1, 0xFF));
    }

    @Test
    void listMatchesGoldenVector() {
        AttributeValue list = AttributeValue.fromL(List.of(
            AttributeValue.fromB(bytes(1, 2, 3, 4, 5)),
            AttributeValue.fromNul(true),
            AttributeValue.fromBool(false)));
        assertGolden(
            list,
            b(0, 0, 0, 3, 0xFF, 0xFF, 0, 0, 0, 5, 1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1, 0),
            b(3, 0));
    }

    @Test
    void mapMatchesGoldenVector() {
        AttributeValue list = AttributeValue.fromL(List.of(
            AttributeValue.fromB(bytes(1, 2, 3, 4, 5)),
            AttributeValue.fromNul(true),
            AttributeValue.fromBool(false)));
        AttributeValue map = AttributeValue.fromM(Map.of(
            "keyA", AttributeValue.fromB(bytes(1, 2, 3, 4, 5)),
            "keyB", AttributeValue.fromNul(true),
            "keyC", AttributeValue.fromBool(false),
            "keyD", list));
        byte[] expected = b(
            0, 0, 0, 4,
            0, 1, 0, 0, 0, 4, 'k', 'e', 'y', 'A', 0xFF, 0xFF, 0, 0, 0, 5, 1, 2, 3, 4, 5,
            0, 1, 0, 0, 0, 4, 'k', 'e', 'y', 'B', 0, 0, 0, 0, 0, 0,
            0, 1, 0, 0, 0, 4, 'k', 'e', 'y', 'C', 0, 4, 0, 0, 0, 1, 0,
            0, 1, 0, 0, 0, 4, 'k', 'e', 'y', 'D', 3, 0, 0, 0, 0, 28,
            0, 0, 0, 3, 0xFF, 0xFF, 0, 0, 0, 5, 1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1, 0);
        assertGolden(map, expected, b(2, 0));
    }

    @Test
    void rejectsDuplicateStringSetEntry() {
        DynamoToStructException thrown = assertThrows(
            DynamoToStructException.class,
            () -> DynamoToStruct.attrToStructured(AttributeValue.fromSs(List.of("a", "a"))));
        assertEquals("String Set had duplicate values", thrown.getMessage());
    }

    @Test
    void rejectsNullTerminalWithNonZeroLength() {
        DynamoToStructException thrown = assertThrows(
            DynamoToStructException.class,
            () -> DynamoToStruct.structuredToAttr(new Terminal(b(0), b(0, 0))));
        assertEquals("NULL type did not have length zero", thrown.getMessage());
    }
}
