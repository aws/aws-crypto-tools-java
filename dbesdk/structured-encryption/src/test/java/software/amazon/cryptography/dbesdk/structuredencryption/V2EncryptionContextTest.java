package software.amazon.cryptography.dbesdk.structuredencryption;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoItem;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Path;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Terminal;

class V2EncryptionContextTest {

    private static final byte[] STRING = {0x00, 0x01};
    private static final byte[] NUMBER = {0x00, 0x02};
    private static final byte[] NULL = {0x00, 0x00};
    private static final byte[] BOOLEAN = {0x00, 0x04};
    private static final byte[] BINARY = {(byte) 0xFF, (byte) 0xFF};

    @Test
    void buildsAttributeEntriesWithLegendSortedByKeyUtf8() {
        List<CryptoItem> fields = List.of(
            signInclude("str", STRING, "hello".getBytes(StandardCharsets.UTF_8)),
            signInclude("num", NUMBER, "123".getBytes(StandardCharsets.UTF_8)),
            signInclude("nul", NULL, new byte[0]),
            signInclude("boolT", BOOLEAN, new byte[] {1}),
            signInclude("boolF", BOOLEAN, new byte[] {0}),
            signInclude("bin", BINARY, new byte[] {0x01, 0x02}),
            new CryptoItem(Path.ofAttribute("enc"), new Terminal("x".getBytes(StandardCharsets.UTF_8), STRING),
                CryptoAction.ENCRYPT_AND_SIGN));

        Map<String, byte[]> context = V2EncryptionContext.build(fields);

        assertEquals(
            Set.of("aws-crypto-attr.bin", "aws-crypto-attr.boolF", "aws-crypto-attr.boolT",
                "aws-crypto-attr.nul", "aws-crypto-attr.num", "aws-crypto-attr.str", "aws-crypto-legend"),
            context.keySet());
        // Sorted key order bin < boolF < boolT < nul < num < str, one char each.
        assertArrayEquals("BLLLNS".getBytes(StandardCharsets.US_ASCII), context.get("aws-crypto-legend"));
        assertArrayEquals("//8BAg==".getBytes(StandardCharsets.US_ASCII), context.get("aws-crypto-attr.bin"));
        assertArrayEquals("false".getBytes(StandardCharsets.US_ASCII), context.get("aws-crypto-attr.boolF"));
        assertArrayEquals("true".getBytes(StandardCharsets.US_ASCII), context.get("aws-crypto-attr.boolT"));
        assertArrayEquals("null".getBytes(StandardCharsets.US_ASCII), context.get("aws-crypto-attr.nul"));
        assertArrayEquals("123".getBytes(StandardCharsets.UTF_8), context.get("aws-crypto-attr.num"));
        assertArrayEquals("hello".getBytes(StandardCharsets.UTF_8), context.get("aws-crypto-attr.str"));
    }

    @Test
    void returnsEmptyWhenNoSignAndIncludeField() {
        List<CryptoItem> fields = List.of(
            new CryptoItem(Path.ofAttribute("a"), new Terminal("x".getBytes(StandardCharsets.UTF_8), STRING),
                CryptoAction.ENCRYPT_AND_SIGN),
            new CryptoItem(Path.ofAttribute("b"), new Terminal("y".getBytes(StandardCharsets.UTF_8), STRING),
                CryptoAction.DO_NOTHING));

        assertTrue(V2EncryptionContext.build(fields).isEmpty());
    }

    @Test
    void rejectsTwoPathsThatProduceTheSameKey() {
        List<CryptoItem> fields = List.of(
            new CryptoItem(Path.ofAttribute("a.b"), new Terminal("x".getBytes(StandardCharsets.UTF_8), STRING),
                CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT),
            new CryptoItem(new Path(List.of("a", "b")), new Terminal("y".getBytes(StandardCharsets.UTF_8), STRING),
                CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT));

        StructuredEncryptionException thrown = assertThrows(
            StructuredEncryptionException.class, () -> V2EncryptionContext.build(fields));
        assertEquals("aws-crypto-attr.a.b appears twice in encryption context.", thrown.getMessage());
    }

    private static CryptoItem signInclude(String name, byte[] typeId, byte[] value) {
        return new CryptoItem(Path.ofAttribute(name), new Terminal(value, typeId),
            CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
    }
}
