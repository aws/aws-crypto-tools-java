package software.amazon.cryptography.dbesdk.structuredencryption.wire;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.dbesdk.structuredencryption.StructuredEncryptionException;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.EncryptedDataKey;

class HeaderTest {

    private static final byte[] MESSAGE_ID = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
    };

    // The serialize() bytes of test/Header.dfy TestRoundTrip's PartialHeader,
    // laid out per the Dafny serialization: version, flavor, msgID, legend,
    // encryption context, encrypted data keys.
    private static final byte[] GOLDEN_PARTIAL_HEADER = {
        1,                                  // version
        1,                                  // flavor
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, // msgID
        0, 2, 0x65, 0x73,                   // legend: length 2, 'e' 's'
        0, 1,                               // encryption context: 1 entry
        0, 3, 0x61, 0x62, 0x63,             // key "abc"
        0, 3, 0x64, 0x65, 0x66,             // value "def"
        1,                                  // encrypted data key count (1 byte)
        0, 6, 0x70, 0x72, 0x6f, 0x76, 0x49, 0x44, // keyProviderId "provID"
        0, 5, 1, 2, 3, 4, 5,                // keyProviderInfo
        0, 4, 6, 7, 8, 9                    // ciphertext
    };

    private static PartialHeader goldenHeader() {
        return new PartialHeader(
            1, (byte) 1, MESSAGE_ID,
            new byte[] {0x65, 0x73},
            Map.of("abc", new byte[] {0x64, 0x65, 0x66}),
            List.of(new EncryptedDataKey(
                "provID".getBytes(StandardCharsets.US_ASCII),
                new byte[] {1, 2, 3, 4, 5},
                new byte[] {6, 7, 8, 9})));
    }

    @Test
    void serializeMatchesDafnyRoundTripVector() {
        assertArrayEquals(GOLDEN_PARTIAL_HEADER, Header.serialize(goldenHeader()));
    }

    /**
     * test/Header.dfy TestDuplicateContext: SerializeContext of {abc:def,
     * cba:fed} orders abc before cba (0x61 < 0x63). Inserted here in reverse to
     * prove the serializer sorts by key bytes, not insertion order.
     */
    @Test
    void serializeContextSortsByKeyBytes() {
        Map<String, byte[]> context = new LinkedHashMap<>();
        context.put("cba", new byte[] {0x66, 0x65, 0x64});
        context.put("abc", new byte[] {0x64, 0x65, 0x66});

        byte[] expected = {
            0, 2,
            0, 3, 0x61, 0x62, 0x63, 0, 3, 0x64, 0x65, 0x66,
            0, 3, 0x63, 0x62, 0x61, 0, 3, 0x66, 0x65, 0x64
        };
        assertArrayEquals(expected, Header.serializeContext(context));
    }

    @Test
    void deserializeRecoversAllFields() {
        byte[] full = new ByteWriter()
            .writeBytes(GOLDEN_PARTIAL_HEADER)
            .writeBytes(new byte[32]) // any 32-byte trailer stands in for the commitment
            .toByteArray();

        PartialHeader parsed = Header.deserialize(full);

        assertEquals(1, parsed.version());
        assertEquals((byte) 1, parsed.flavor());
        assertArrayEquals(MESSAGE_ID, parsed.messageId());
        assertArrayEquals(new byte[] {0x65, 0x73}, parsed.legend());
        assertEquals(1, parsed.encryptionContext().size());
        assertArrayEquals(new byte[] {0x64, 0x65, 0x66}, parsed.encryptionContext().get("abc"));
        assertEquals(1, parsed.dataKeys().size());
        EncryptedDataKey edk = parsed.dataKeys().get(0);
        assertArrayEquals("provID".getBytes(StandardCharsets.US_ASCII), edk.keyProviderId());
        assertArrayEquals(new byte[] {1, 2, 3, 4, 5}, edk.keyProviderInfo());
        assertArrayEquals(new byte[] {6, 7, 8, 9}, edk.ciphertext());
    }

    /** test/Header.dfy TestOutOfOrderContext: abc after cba is rejected. */
    @Test
    void readContextRejectsOutOfOrderKeys() {
        byte[] outOfOrder = {
            0, 2,
            0, 3, 0x63, 0x62, 0x61, 0, 3, 0x66, 0x65, 0x64, // "cba"
            0, 3, 0x61, 0x62, 0x63, 0, 3, 0x64, 0x65, 0x66  // "abc" — out of order
        };

        StructuredEncryptionException thrown = assertThrows(
            StructuredEncryptionException.class,
            () -> Header.readContext(new ByteReader(outOfOrder)));
        assertEquals("Context keys out of order.", thrown.getMessage());
    }

    /** test/Header.dfy TestDuplicateContext: a repeated key surfaces as out of order. */
    @Test
    void readContextRejectsDuplicateKeys() {
        byte[] duplicate = {
            0, 3,
            0, 3, 0x61, 0x62, 0x63, 0, 3, 0x64, 0x65, 0x66, // "abc"
            0, 3, 0x63, 0x62, 0x61, 0, 3, 0x66, 0x65, 0x64, // "cba"
            0, 3, 0x61, 0x62, 0x63, 0, 3, 0x65, 0x64, 0x66  // "abc" again
        };

        StructuredEncryptionException thrown = assertThrows(
            StructuredEncryptionException.class,
            () -> Header.readContext(new ByteReader(duplicate)));
        assertEquals("Context keys out of order.", thrown.getMessage());
    }

    @Test
    void deserializeRejectsZeroDataKeys() {
        byte[] noDataKeys = new ByteWriter()
            .writeByte(1).writeByte(1).writeBytes(MESSAGE_ID)
            .writeBytes(new byte[] {0, 0}) // empty legend
            .writeBytes(new byte[] {0, 0}) // empty encryption context
            .writeByte(0)                  // zero data keys
            .toByteArray();

        StructuredEncryptionException thrown = assertThrows(
            StructuredEncryptionException.class,
            () -> Header.deserialize(noDataKeys));
        assertEquals("At least one Data Key required", thrown.getMessage());
    }

    @Test
    void commitmentVerifiesAndRejectsTamper() {
        byte[] commitKey = MESSAGE_ID;
        byte[] full = Header.serializeWithCommitment(goldenHeader(), commitKey, "HmacSHA384");

        assertEquals(GOLDEN_PARTIAL_HEADER.length + 32, full.length);
        Header.verifyCommitment(commitKey, full, "HmacSHA384"); // no throw

        byte[] tampered = full.clone();
        tampered[tampered.length - 1] ^= 0x01;
        StructuredEncryptionException thrown = assertThrows(
            StructuredEncryptionException.class,
            () -> Header.verifyCommitment(commitKey, tampered, "HmacSHA384"));
        assertEquals("Key commitment mismatch.", thrown.getMessage());
    }
}
