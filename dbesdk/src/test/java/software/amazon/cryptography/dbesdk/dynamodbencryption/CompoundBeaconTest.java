package software.amazon.cryptography.dbesdk.dynamodbencryption;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

class CompoundBeaconTest {

    private static BeaconPart.Signed signed(String prefix, String name) {
        return new BeaconPart.Signed(prefix, name, TermLoc.make(name));
    }

    @Test
    void nakedValueJoinsSignedPartsOnSplit() {
        CompoundBeacon cb = CompoundBeacon.create(
            "cb", '.', List.of(signed("P_", "p"), signed("S_", "s")), List.of());
        Map<String, AttributeValue> item =
            Map.of("p", AttributeValue.fromS("x"), "s", AttributeValue.fromS("y"));
        assertEquals(Optional.of("P_x.S_y"), cb.getValue(item, Map.of(), null, 0));
    }

    @Test
    void encryptedPartHashesValueUnderItsKey() {
        StandardBeacon beacon = StandardBeacon.create("e", 16, "e", false, 0);
        BeaconPart.Encrypted enc = new BeaconPart.Encrypted("E_", beacon);
        CompoundBeacon cb = CompoundBeacon.create("cb", '.', List.of(enc), List.of());
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 9);
        Map<String, AttributeValue> item = Map.of("e", AttributeValue.fromS("val"));

        Optional<String> value = cb.getValue(item, Map.of(), Map.of("e", key), 0);

        String expectedHash = beacon.hash("val".getBytes(StandardCharsets.UTF_8), key, 0);
        assertEquals(Optional.of("E_" + expectedHash), value);
    }

    @Test
    void requiredAbsentPartFallsToNextConstructor() {
        BeaconPart p = signed("P_", "p");
        BeaconPart s = signed("S_", "s");
        CompoundBeacon cb = CompoundBeacon.create("cb", '.', List.of(p, s), List.of(
            List.of(new CompoundBeacon.ConstructorPart(p, true), new CompoundBeacon.ConstructorPart(s, true)),
            List.of(new CompoundBeacon.ConstructorPart(p, true))));
        Map<String, AttributeValue> item = Map.of("p", AttributeValue.fromS("x"));
        assertEquals(Optional.of("P_x"), cb.getValue(item, Map.of(), null, 0));
    }

    @Test
    void optionalAbsentPartIsSkipped() {
        BeaconPart p = signed("P_", "p");
        BeaconPart s = signed("S_", "s");
        CompoundBeacon cb = CompoundBeacon.create("cb", '.', List.of(p, s), List.of(
            List.of(new CompoundBeacon.ConstructorPart(p, true), new CompoundBeacon.ConstructorPart(s, false))));
        Map<String, AttributeValue> item = Map.of("p", AttributeValue.fromS("x"));
        assertEquals(Optional.of("P_x"), cb.getValue(item, Map.of(), null, 0));
    }

    @Test
    void valueContainingSplitCharacterFails() {
        CompoundBeacon cb = CompoundBeacon.create("cb", '.', List.of(signed("P_", "p")), List.of());
        Map<String, AttributeValue> item = Map.of("p", AttributeValue.fromS("has.dot"));
        assertThrows(BeaconException.class, () -> cb.getValue(item, Map.of(), null, 0));
    }

    @Test
    void overlappingPrefixesFailAtConstruction() {
        BeaconPart a = signed("P_", "a");
        BeaconPart b = signed("P_X", "b");
        assertThrows(BeaconException.class,
            () -> CompoundBeacon.create("cb", '.', List.of(a, b), List.of()));
    }

    @Test
    void queryEqualityBeaconMatchesWrittenValue() {
        StandardBeacon beacon = StandardBeacon.create("e", 16, "e", false, 0);
        BeaconPart s = signed("S_", "s");
        BeaconPart.Encrypted enc = new BeaconPart.Encrypted("E_", beacon);
        CompoundBeacon cb = CompoundBeacon.create("cb", '.', List.of(s, enc), List.of());
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 9);
        Map<String, byte[]> keys = Map.of("e", key);

        String written = cb.getValue(
            Map.of("s", AttributeValue.fromS("foo"), "e", AttributeValue.fromS("bar")),
            Map.of(), keys, 0).orElseThrow();
        AttributeValue queried = cb.getBeaconValue(AttributeValue.fromS("S_foo.E_bar"), keys, true, 0);

        assertEquals(written, queried.s());
    }

    @Test
    void beginsWithQueryKeepsBarePrefixRaw() {
        StandardBeacon beacon = StandardBeacon.create("e", 16, "e", false, 0);
        CompoundBeacon cb = CompoundBeacon.create(
            "cb", '.', List.of(signed("S_", "s"), new BeaconPart.Encrypted("E_", beacon)), List.of());
        byte[] key = new byte[32];
        Map<String, byte[]> keys = Map.of("e", key);

        AttributeValue queried = cb.getBeaconValue(AttributeValue.fromS("S_foo.E_"), keys, false, 0);

        assertEquals("S_foo.E_", queried.s());
    }

    @Test
    void findPartFailsWhenNoPrefixMatches() {
        CompoundBeacon cb = CompoundBeacon.create("cb", '.', List.of(signed("S_", "s")), List.of());
        assertThrows(BeaconException.class, () -> cb.findPart("Z_x"));
    }

    @Test
    void getFieldsFlattensPartsExpandingVirtualFields() {
        VirtualField vf = VirtualField.create("v", List.of(
            new VirtualField.Part(TermLoc.make("x"), List.of()),
            new VirtualField.Part(TermLoc.make("y"), List.of())));
        CompoundBeacon cb = CompoundBeacon.create(
            "cb", '.', List.of(signed("A_", "a"), signed("V_", "v")), List.of());

        assertEquals(List.of("a", "x", "y"), cb.getFields(Map.of("v", vf)));
    }

    @Test
    void keyIdFromValueStripsPrefixOfTheSignedKeyPart() {
        StandardBeacon beacon = StandardBeacon.create("e", 16, "e", false, 0);
        CompoundBeacon cb = CompoundBeacon.create("cb", '.',
            List.of(signed("K_", "tenant"), new BeaconPart.Encrypted("E_", beacon)), List.of());

        assertEquals(Optional.of("tenant1"), cb.keyIdFromValue("tenant", "K_tenant1.E_foo"));
    }

    @Test
    void keyIdFromValueEmptyWhenNoPartReadsTheField() {
        CompoundBeacon cb = CompoundBeacon.create("cb", '.',
            List.of(signed("K_", "tenant"), signed("S_", "s")), List.of());

        assertEquals(Optional.empty(), cb.keyIdFromValue("missing", "K_tenant1.S_foo"));
    }
}
