package software.amazon.cryptography.dbesdk.dynamodbencryption;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

class StandardBeaconTest {

    // The HMAC-SHA384-first-8 of value [1,2,3] under key [1,2], from test/Beacon.dfy.
    private static final byte[] HMAC_OF_123 = {
        0x27, (byte) 0x93, (byte) 0x93, (byte) 0x8b, 0x26, (byte) 0xe9, 0x52, 0x7e
    };
    private static final byte[] VALUE_123 = {1, 2, 3};
    private static final byte[] KEY = {1, 2};
    // test/Beacon.dfy TestOneBeaconValue uses this base key for the end-to-end vectors.
    private static final byte[] BASE_KEY = {1, 2, 3, 4, 5};

    private static StandardBeacon primitive(int lengthBits, int numberOfPartitions) {
        return StandardBeacon.create("test", lengthBits, "field", false, numberOfPartitions);
    }

    @Test
    void getHmacMatchesDafnyVector() {
        assertArrayEquals(HMAC_OF_123, StandardBeacon.getHmac(VALUE_123, KEY));
        // Partition byte appended before hashing (Beacon spec §4):
        assertArrayEquals(
            new byte[] {42, 100, (byte) 242, 20, (byte) 188, 0, 33, 0x1d},
            StandardBeacon.getHmac(new byte[] {1, 2, 3, 1}, KEY));
        assertArrayEquals(
            new byte[] {53, (byte) 151, (byte) 144, 34, 49, 19, (byte) 169, (byte) 0xef},
            StandardBeacon.getHmac(new byte[] {1, 2, 3, 2}, KEY));
    }

    @Test
    void basicHashMatchesDafnyVectors() {
        // test/Beacon.dfy: StandardBeacon(.., length 8, .., numberOfPartitions 5).
        StandardBeacon beacon = primitive(8, 5);
        assertEquals("7e", beacon.hash(VALUE_123, KEY, 0));
        assertEquals("1d", beacon.hash(VALUE_123, KEY, 1));
        assertEquals("ef", beacon.hash(VALUE_123, KEY, 2));
    }

    @Test
    void basicHashOfEmptyValue() {
        // test/Beacon.dfy: hash([], key [1,2], partition 0) == "80".
        assertEquals("80", primitive(8, 5).hash(new byte[0], KEY, 0));
    }

    @Test
    void bytesToHexKeepsRightmostBitsAsLowercaseHex() {
        // Byte-aligned lengths render the rightmost length/8 bytes in full (length 8
        // anchored to the Dafny "7e" golden); the others apply the same algorithm to the
        // same real MAC bytes.
        assertEquals("7e", StandardBeacon.bytesToHex(HMAC_OF_123, 8));
        assertEquals("527e", StandardBeacon.bytesToHex(HMAC_OF_123, 16));
        assertEquals("e9527e", StandardBeacon.bytesToHex(HMAC_OF_123, 24));
        assertEquals("26e9527e", StandardBeacon.bytesToHex(HMAC_OF_123, 32));
    }

    @Test
    void bytesToHexTruncatesLeadingNibbleForNonByteAlignedLengths() {
        // 26 bits: 7 chars, leading nibble (low nibble of byte 0x26 = 6) truncated to
        // 26 mod 4 = 2 bits -> 6 & 3 = 2.
        assertEquals("2e9527e", StandardBeacon.bytesToHex(HMAC_OF_123, 26));
        // 28 bits: 7 chars, leading nibble kept to 4 bits (28 mod 4 == 0) -> 6. Distinct
        // from the 26-bit case, and would differ if the high nibble were used instead.
        assertEquals("6e9527e", StandardBeacon.bytesToHex(HMAC_OF_123, 28));
    }

    @Test
    void partitionIsReducedModuloPartitionCount() {
        StandardBeacon beacon = primitive(8, 5);
        // 7 % 5 == 2, so the beacon value equals partition 2's ("ef").
        assertEquals("ef", beacon.hash(VALUE_123, KEY, 7));
        // 5 % 5 == 0, which encodes nothing, so it equals partition 0's ("7e").
        assertEquals("7e", beacon.hash(VALUE_123, KEY, 5));
    }

    @Test
    void unconstrainedBeaconEncodesPartitionAsIs() {
        // numberOfPartitions 0: no modulo, so partition 1 appends byte [1] directly.
        StandardBeacon beacon = primitive(8, 0);
        assertEquals("7e", beacon.hash(VALUE_123, KEY, 0));
        assertEquals("1d", beacon.hash(VALUE_123, KEY, 1));
    }

    @Test
    void rejectsBeaconLengthOutsideOneToSixtyThree() {
        assertThrows(BeaconException.class, () -> primitive(0, 0));
        assertThrows(BeaconException.class, () -> primitive(64, 0));
    }

    @Test
    void rejectsPartitionCountOutsideZeroToTwoFiftyFive() {
        assertThrows(BeaconException.class, () -> primitive(8, -1));
        assertThrows(BeaconException.class, () -> primitive(8, 256));
    }

    @Test
    void rejectsPartitionNumberOutsideZeroToTwoFiftyFour() {
        StandardBeacon beacon = primitive(8, 5);
        assertThrows(BeaconException.class, () -> beacon.hash(VALUE_123, KEY, -1));
        assertThrows(BeaconException.class, () -> beacon.hash(VALUE_123, KEY, 255));
    }

    @Test
    void getHashOfTopLevelValueMatchesDafnyGolden() {
        // Item layer end-to-end: locate "std4" -> serialize S("abc") -> hash, reproducing
        // the test/Beacon.dfy TestOneBeaconValue std4 golden (len 24, base key [1,2,3,4,5]).
        byte[] key = BeaconKeyDerivation.deriveBeaconKey(BASE_KEY, "std4");
        StandardBeacon beacon = StandardBeacon.create("std4", 24, "std4", false, 0);
        Optional<AttributeValue> result =
            beacon.getHash(Map.of("std4", AttributeValue.fromS("abc")), key, 0);
        assertEquals(Optional.of(AttributeValue.fromS("0e9064")), result);
    }

    @Test
    void getHashLocatesValueThroughNestedPath() {
        // Same golden value, but the source value sits at "a.b" — proves navigation feeds
        // the located value's bytes to the hash unchanged.
        byte[] key = BeaconKeyDerivation.deriveBeaconKey(BASE_KEY, "std4");
        StandardBeacon beacon = StandardBeacon.create("std4", 24, "a.b", false, 0);
        Map<String, AttributeValue> item =
            Map.of("a", AttributeValue.fromM(Map.of("b", AttributeValue.fromS("abc"))));
        assertEquals(Optional.of(AttributeValue.fromS("0e9064")), beacon.getHash(item, key, 0));
    }

    @Test
    void getHashOfAbsentFieldIsEmpty() {
        byte[] key = BeaconKeyDerivation.deriveBeaconKey(BASE_KEY, "std4");
        StandardBeacon beacon = StandardBeacon.create("std4", 24, "std4", false, 0);
        assertEquals(Optional.empty(), beacon.getHash(Map.of(), key, 0));
    }

    @Test
    void getHashOfSetBeaconizesEachElementInOrder() {
        byte[] key = BeaconKeyDerivation.deriveBeaconKey(BASE_KEY, "setb");
        StandardBeacon beacon = StandardBeacon.create("setb", 32, "s", true, 0);
        // The two elements beacon to distinct 32-bit values, computed via the primitive on
        // each single-element serialization — the set path must reproduce them, in order.
        String first = beacon.hash(DynamoToStruct.attrToStructured(AttributeValue.fromS("abc")).value(), key, 0);
        String second = beacon.hash(DynamoToStruct.attrToStructured(AttributeValue.fromS("xyz")).value(), key, 0);
        Optional<AttributeValue> result =
            beacon.getHash(Map.of("s", AttributeValue.fromSs(List.of("abc", "xyz"))), key, 0);
        assertEquals(Optional.of(AttributeValue.fromSs(List.of(first, second))), result);
    }

    @Test
    void getHashOfSetDedupesCollidingBeaconValues() {
        // At length 1 there are only two possible beacon values, so three distinct inputs
        // must collapse to at most two entries — proving the output is deduped (without
        // dedup the result would carry all three).
        byte[] key = BeaconKeyDerivation.deriveBeaconKey(BASE_KEY, "setd");
        StandardBeacon beacon = StandardBeacon.create("setd", 1, "s", true, 0);
        Optional<AttributeValue> result =
            beacon.getHash(Map.of("s", AttributeValue.fromSs(List.of("a", "b", "c"))), key, 0);
        assertTrue(result.isPresent());
        assertTrue(result.get().ss().size() < 3);
    }

    @Test
    void getHashOfSetBeaconOverNonSetValueFails() {
        byte[] key = BeaconKeyDerivation.deriveBeaconKey(BASE_KEY, "setb");
        StandardBeacon beacon = StandardBeacon.create("setb", 32, "s", true, 0);
        Map<String, AttributeValue> item = Map.of("s", AttributeValue.fromS("notaset"));
        assertThrows(BeaconException.class, () -> beacon.getHash(item, key, 0));
    }

    @Test
    void getHashOfAbsentSetFieldIsEmpty() {
        byte[] key = BeaconKeyDerivation.deriveBeaconKey(BASE_KEY, "setb");
        StandardBeacon beacon = StandardBeacon.create("setb", 32, "s", true, 0);
        assertEquals(Optional.empty(), beacon.getHash(Map.of(), key, 0));
    }
}
