package software.amazon.cryptography.dbesdk.dynamodbencryption;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

class BeaconKeyDerivationTest {

    private static final byte[] BASE_KEY = {1, 2, 3, 4, 5};

    @Test
    void deriveBeaconKeyProducesSixtyFourBytes() {
        assertEquals(64, BeaconKeyDerivation.deriveBeaconKey(BASE_KEY, "std2").length);
    }

    @Test
    void endToEndBeaconValuesMatchDafnyGoldenVectors() {
        // test/Beacon.dfy TestOneBeaconValue, base key [1,2,3,4,5]: HKDF-SHA512 derive ->
        // DynamoToStruct value bytes -> StandardBeacon basicHash. Reproducing these pins the
        // whole native stack (derivation + serialization + primitive) to the Dafny reference.
        assertEquals("ac6f5d", beacon("std2", AttributeValue.fromN("1.23"), 24));
        assertEquals("7d9bfa40", beacon("Name", AttributeValue.fromS("MyName"), 32));
        assertEquals("e4feb833", beacon("Title", AttributeValue.fromS("MyTitle"), 32));
        assertEquals("0e9064", beacon("std4", AttributeValue.fromS("abc"), 24));
        assertEquals("2d99222", beacon("std6", AttributeValue.fromS("666"), 26));
        assertEquals("4c577d7", beacon("NameTitleField", AttributeValue.fromS("MyName__mytitle"), 28));
        assertEquals("e0e88994", beacon("Name", AttributeValue.fromS(""), 32));
        assertEquals("af34f26f", beacon("Title", AttributeValue.fromS(""), 32));
    }

    @Test
    void numberValueIsNormalizedBeforeHashing() {
        // test/Beacon.dfy TestNumbersNormalize: N("1.23") and N("000001.23000000") beacon equal.
        assertEquals(
            beacon("std2", AttributeValue.fromN("1.23"), 24),
            beacon("std2", AttributeValue.fromN("000001.23000000"), 24));
    }

    @Test
    void deriveHmacKeysBuildsOneKeyPerName() {
        Map<String, byte[]> keys =
            BeaconKeyDerivation.deriveHmacKeys(BASE_KEY, List.of("std2", "Name"));
        assertEquals(2, keys.size());
        assertArrayEquals(BeaconKeyDerivation.deriveBeaconKey(BASE_KEY, "std2"), keys.get("std2"));
        assertArrayEquals(BeaconKeyDerivation.deriveBeaconKey(BASE_KEY, "Name"), keys.get("Name"));
    }

    @Test
    void deriveHmacKeysRejectsDuplicateName() {
        assertThrows(
            BeaconException.class,
            () -> BeaconKeyDerivation.deriveHmacKeys(BASE_KEY, List.of("std2", "std2")));
    }

    private static String beacon(String name, AttributeValue value, int lengthBits) {
        byte[] key = BeaconKeyDerivation.deriveBeaconKey(BASE_KEY, name);
        byte[] valueBytes = DynamoToStruct.attrToStructured(value).value();
        return StandardBeacon.create(name, lengthBits, name, false, 0).hash(valueBytes, key, 0);
    }
}
