package software.amazon.cryptography.dbesdk.dynamodbencryption;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

class BeaconVersionTest {

    private static final byte[] BASE_KEY = {1, 2, 3, 4, 5};

    private static Map<String, AttributeValue> generate(
            BeaconVersion version, Map<String, AttributeValue> item) {
        Map<String, byte[]> keys = BeaconKeyDerivation.deriveHmacKeys(BASE_KEY, version.beaconNames());
        return version.generateEncryptedBeacons(item, keys, 0);
    }

    @Test
    void generatesBeaconAttributesMatchingDafnyGoldenVectors() {
        // Compose config->beacons + GenerateEncryptedBeacons over the already-pinned
        // derivation+primitive: the aws_dbe_b_ values must equal the test/Beacon.dfy goldens
        // (base key [1,2,3,4,5]); loc defaults to the beacon name, so each reads its own attr.
        BeaconVersion version = BeaconVersion.of(List.of(
            StandardBeacon.create("std2", 24, "std2", false, 0),
            StandardBeacon.create("Name", 32, "Name", false, 0),
            StandardBeacon.create("std4", 24, "std4", false, 0)));
        Map<String, AttributeValue> item = Map.of(
            "std2", AttributeValue.fromN("1.23"),
            "Name", AttributeValue.fromS("MyName"),
            "std4", AttributeValue.fromS("abc"));

        Map<String, AttributeValue> beacons = generate(version, item);

        assertEquals(AttributeValue.fromS("ac6f5d"), beacons.get("aws_dbe_b_std2"));
        assertEquals(AttributeValue.fromS("7d9bfa40"), beacons.get("aws_dbe_b_Name"));
        assertEquals(AttributeValue.fromS("0e9064"), beacons.get("aws_dbe_b_std4"));
        assertEquals(3, beacons.size());
    }

    @Test
    void sharedBeaconMatchesTheBeaconItSharesWith() {
        // alias shares first's key, reads its own (equal) value -> same beacon value.
        BeaconVersion shared = BeaconVersion.of(List.of(
            StandardBeacon.create("first", 10, "first", false, 0),
            StandardBeacon.create("alias", 10, "alias", false, 0, "first", false)));
        Map<String, AttributeValue> item = Map.of(
            "first", AttributeValue.fromS("john"),
            "alias", AttributeValue.fromS("john"));

        Map<String, AttributeValue> beacons = generate(shared, item);

        assertEquals(beacons.get("aws_dbe_b_first"), beacons.get("aws_dbe_b_alias"));
    }

    @Test
    void independentBeaconsOnEqualValuesDiffer() {
        // Control for the shared case: distinct per-name keys -> distinct beacons.
        BeaconVersion independent = BeaconVersion.of(List.of(
            StandardBeacon.create("first", 10, "first", false, 0),
            StandardBeacon.create("alias", 10, "alias", false, 0)));
        Map<String, AttributeValue> item = Map.of(
            "first", AttributeValue.fromS("john"),
            "alias", AttributeValue.fromS("john"));

        Map<String, AttributeValue> beacons = generate(independent, item);

        assertNotEquals(beacons.get("aws_dbe_b_first"), beacons.get("aws_dbe_b_alias"));
    }

    @Test
    void partOnlyBeaconIsNotWritten() {
        BeaconVersion version = BeaconVersion.of(List.of(
            StandardBeacon.create("part", 10, "part", false, 0, null, true),
            StandardBeacon.create("plain", 10, "plain", false, 0)));
        Map<String, AttributeValue> item = Map.of(
            "part", AttributeValue.fromS("x"),
            "plain", AttributeValue.fromS("y"));

        Map<String, AttributeValue> beacons = generate(version, item);

        assertFalse(beacons.containsKey("aws_dbe_b_part"));
        assertTrue(beacons.containsKey("aws_dbe_b_plain"));
    }

    @Test
    void absentSourceFieldProducesNoBeacon() {
        BeaconVersion version = BeaconVersion.of(List.of(
            StandardBeacon.create("present", 10, "present", false, 0),
            StandardBeacon.create("missing", 10, "missing", false, 0)));
        Map<String, AttributeValue> item = Map.of("present", AttributeValue.fromS("here"));

        Map<String, AttributeValue> beacons = generate(version, item);

        assertEquals(1, beacons.size());
        assertTrue(beacons.containsKey("aws_dbe_b_present"));
    }

    @Test
    void rejectsDuplicateBeaconName() {
        assertThrows(BeaconException.class, () -> BeaconVersion.of(List.of(
            StandardBeacon.create("dup", 10, "dup", false, 0),
            StandardBeacon.create("dup", 12, "dup", false, 0))));
    }

    @Test
    void encryptedCompoundBeaconWrittenUnderPrefix() {
        // A compound beacon with an encrypted part is encrypted, so it is written after
        // encryption as aws_dbe_b_<name>: signed part plaintext, encrypted part the hash of
        // its UTF-8 value, joined on the split char. The referenced standard beacon is
        // PartOnly, so it supplies a key but is never written on its own.
        StandardBeacon encBeacon = StandardBeacon.create("enc", 24, "e", false, 0, null, true);
        CompoundBeacon comp = CompoundBeacon.create("comp", '.', List.of(
            new BeaconPart.Signed("S_", "sig", TermLoc.make("s")),
            new BeaconPart.Encrypted("E_", encBeacon)), List.of());
        BeaconVersion version = BeaconVersion.create(
            List.of(new Beacon.Standard(encBeacon), new Beacon.Compound(comp)), Map.of());
        Map<String, AttributeValue> item = Map.of(
            "s", AttributeValue.fromS("foo"), "e", AttributeValue.fromS("bar"));

        Map<String, byte[]> keys = BeaconKeyDerivation.deriveHmacKeys(BASE_KEY, version.beaconNames());
        Map<String, AttributeValue> beacons = version.generateEncryptedBeacons(item, keys, 0);

        String encHash = encBeacon.hash("bar".getBytes(StandardCharsets.UTF_8), keys.get("enc"), 0);
        assertEquals(AttributeValue.fromS("S_foo.E_" + encHash), beacons.get("aws_dbe_b_comp"));
        assertFalse(beacons.containsKey("aws_dbe_b_enc"));
    }

    @Test
    void fullySignedCompoundBeaconWrittenAsNameBeforeEncryption() {
        // A compound beacon with only signed parts is not encrypted: it is signed into the
        // item before encryption as <name> (no aws_dbe_b_ prefix), from plaintext part
        // values, and is excluded from the encrypted pass.
        CompoundBeacon sigComp = CompoundBeacon.create("sigComp", '.', List.of(
            new BeaconPart.Signed("F_", "fn", TermLoc.make("fn")),
            new BeaconPart.Signed("L_", "ln", TermLoc.make("ln"))), List.of());
        BeaconVersion version = BeaconVersion.create(List.of(new Beacon.Compound(sigComp)), Map.of());
        Map<String, AttributeValue> item = Map.of(
            "fn", AttributeValue.fromS("john"), "ln", AttributeValue.fromS("doe"));

        Map<String, AttributeValue> signed = version.generateSignedBeacons(item, 0);
        assertEquals(Map.of("sigComp", AttributeValue.fromS("F_john.L_doe")), signed);

        Map<String, AttributeValue> encrypted = version.generateEncryptedBeacons(item, Map.of(), 0);
        assertTrue(encrypted.isEmpty());
    }

    @Test
    void standardBeaconOverVirtualFieldHashesTheFieldValue() {
        // A standard beacon whose location names a virtual field hashes the UTF-8 bytes of
        // the field's concatenated value (VirtToBytes), not the located attribute's bytes.
        VirtualField full = VirtualField.create("full", List.of(
            new VirtualField.Part(TermLoc.make("first"), List.of()),
            new VirtualField.Part(TermLoc.make("last"), List.of())));
        StandardBeacon beacon = StandardBeacon.create("full", 24, "full", false, 0);
        BeaconVersion version = BeaconVersion.create(
            List.of(new Beacon.Standard(beacon)), Map.of("full", full));
        Map<String, AttributeValue> item = Map.of(
            "first", AttributeValue.fromS("John"), "last", AttributeValue.fromS("Doe"));

        Map<String, byte[]> keys = BeaconKeyDerivation.deriveHmacKeys(BASE_KEY, version.beaconNames());
        Map<String, AttributeValue> beacons = version.generateEncryptedBeacons(item, keys, 0);

        String expected = beacon.hash("JohnDoe".getBytes(StandardCharsets.UTF_8), keys.get("full"), 0);
        assertEquals(AttributeValue.fromS(expected), beacons.get("aws_dbe_b_full"));
    }

    @Test
    void generatePlainBeaconsComputesEveryBeaconKeylessUnderItsBeaconName() {
        // The output filter recomputes every beacon from the decrypted plaintext, keyless:
        // each appears under its beaconName with a PLAINTEXT (naked) value — a standard beacon
        // as its located value, a compound beacon as the prefix+plaintext assembly with NO
        // hashing (the distinction from generateEncryptedBeacons, which hashes the encrypted
        // part). A PartOnly beacon is still excluded.
        StandardBeacon encPart = StandardBeacon.create("enc", 24, "e", false, 0, null, true);
        CompoundBeacon comp = CompoundBeacon.create("comp", '.', List.of(
            new BeaconPart.Signed("S_", "sg", TermLoc.make("sg")),
            new BeaconPart.Encrypted("E_", encPart)), List.of());
        BeaconVersion version = BeaconVersion.create(List.of(
            new Beacon.Standard(StandardBeacon.create("color", 10, "color", false, 0)),
            new Beacon.Standard(encPart),
            new Beacon.Compound(comp)), Map.of());
        Map<String, AttributeValue> item = Map.of(
            "color", AttributeValue.fromS("red"),
            "sg", AttributeValue.fromS("x"),
            "e", AttributeValue.fromS("bar"));

        Map<String, AttributeValue> plain = version.generatePlainBeacons(item, 0);

        assertEquals(AttributeValue.fromS("red"), plain.get("aws_dbe_b_color"));
        assertEquals(AttributeValue.fromS("S_x.E_bar"), plain.get("aws_dbe_b_comp"));
        assertFalse(plain.containsKey("aws_dbe_b_enc"));
    }

    @Test
    void listSignedBeaconsReturnsOnlyFullySignedCompoundBeacons() {
        // Standard beacons are always encrypted, and a compound beacon with an encrypted part
        // is encrypted; only a compound beacon whose parts are all signed is a signed beacon.
        StandardBeacon partBeacon = StandardBeacon.create("e", 24, "e", false, 0, null, true);
        CompoundBeacon signedComp = CompoundBeacon.create("sig", '.', List.of(
            new BeaconPart.Signed("F_", "fn", TermLoc.make("fn")),
            new BeaconPart.Signed("L_", "ln", TermLoc.make("ln"))), List.of());
        CompoundBeacon encryptedComp = CompoundBeacon.create("enc", '.', List.of(
            new BeaconPart.Signed("S_", "sg", TermLoc.make("sg")),
            new BeaconPart.Encrypted("E_", partBeacon)), List.of());
        BeaconVersion version = BeaconVersion.create(List.of(
            new Beacon.Standard(StandardBeacon.create("s", 24, "s", false, 0)),
            new Beacon.Standard(partBeacon),
            new Beacon.Compound(signedComp),
            new Beacon.Compound(encryptedComp)), Map.of());

        assertEquals(List.of("sig"), version.listSignedBeacons());
    }
}
