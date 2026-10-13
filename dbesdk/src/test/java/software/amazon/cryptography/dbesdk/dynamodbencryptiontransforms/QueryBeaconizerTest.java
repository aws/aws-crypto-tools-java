package software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbesdk.dynamodbencryption.Beacon;
import software.amazon.cryptography.dbesdk.dynamodbencryption.BeaconKeyDerivation;
import software.amazon.cryptography.dbesdk.dynamodbencryption.BeaconPart;
import software.amazon.cryptography.dbesdk.dynamodbencryption.BeaconVersion;
import software.amazon.cryptography.dbesdk.dynamodbencryption.CompoundBeacon;
import software.amazon.cryptography.dbesdk.dynamodbencryption.MaybeKeyMap;
import software.amazon.cryptography.dbesdk.dynamodbencryption.StandardBeacon;
import software.amazon.cryptography.dbesdk.dynamodbencryption.TermLoc;

class QueryBeaconizerTest {

    private static final byte[] BASE_KEY = {1, 2, 3, 4, 5};

    private static MaybeKeyMap keysFor(BeaconVersion version) {
        return new MaybeKeyMap.Keys(BeaconKeyDerivation.deriveHmacKeys(BASE_KEY, version.beaconNames()));
    }

    @Test
    void equalityRewritesAttrToBeaconNameAndBeaconizesValue() {
        StandardBeacon foo = StandardBeacon.create("foo", 24, "foo", false, 0);
        BeaconVersion version = BeaconVersion.of(List.of(foo));
        MaybeKeyMap keys = keysFor(version);
        ExprContext in = new ExprContext(
            "foo = :v", null, Map.of(":v", AttributeValue.fromS("hello")), null);

        ExprContext out = QueryBeaconizer.beaconize(version, in, keys, 0);

        assertEquals("aws_dbe_b_foo = :v", out.keyExpr());
        AttributeValue expected = foo.getBeaconValue(
            AttributeValue.fromS("hello"), ((MaybeKeyMap.Keys) keys).keys().get("foo"), false, 0);
        assertEquals(expected, out.values().get(":v"));
    }

    @Test
    void attributeExistsDoesNotBeaconizeItsOperand() {
        BeaconVersion version = BeaconVersion.of(List.of(StandardBeacon.create("foo", 24, "foo", false, 0)));
        ExprContext in = new ExprContext("attribute_exists(foo)", null, null, null);

        ExprContext out = QueryBeaconizer.beaconize(version, in, keysFor(version), 0);

        assertEquals("attribute_exists ( foo )", out.keyExpr());
    }

    @Test
    void nonBeaconAttributePassesThroughUnchanged() {
        BeaconVersion version = BeaconVersion.of(List.of(StandardBeacon.create("foo", 24, "foo", false, 0)));
        ExprContext in = new ExprContext(
            "plain = :v", null, Map.of(":v", AttributeValue.fromS("x")), null);

        ExprContext out = QueryBeaconizer.beaconize(version, in, keysFor(version), 0);

        assertEquals("plain = :v", out.keyExpr());
        assertEquals(AttributeValue.fromS("x"), out.values().get(":v"));
    }

    @Test
    void indirectNameIsRemappedToBeaconNameInNamesMap() {
        StandardBeacon foo = StandardBeacon.create("foo", 24, "foo", false, 0);
        BeaconVersion version = BeaconVersion.of(List.of(foo));
        MaybeKeyMap keys = keysFor(version);
        ExprContext in = new ExprContext(
            "#a = :v", null, Map.of(":v", AttributeValue.fromS("hello")), Map.of("#a", "foo"));

        ExprContext out = QueryBeaconizer.beaconize(version, in, keys, 0);

        assertEquals("#a = :v", out.keyExpr());
        assertEquals("aws_dbe_b_foo", out.names().get("#a"));
        AttributeValue expected = foo.getBeaconValue(
            AttributeValue.fromS("hello"), ((MaybeKeyMap.Keys) keys).keys().get("foo"), false, 0);
        assertEquals(expected, out.values().get(":v"));
    }

    @Test
    void sizeOnBeaconIsRejected() {
        BeaconVersion version = BeaconVersion.of(List.of(StandardBeacon.create("foo", 24, "foo", false, 0)));
        ExprContext in = new ExprContext(
            "size(foo) > :v", null, Map.of(":v", AttributeValue.fromN("5")), null);

        DynamoDbEncryptionTransformsException ex = assertThrows(
            DynamoDbEncryptionTransformsException.class,
            () -> QueryBeaconizer.beaconize(version, in, keysFor(version), 0));
        assertTrue(ex.getMessage().contains("size"));
    }

    @Test
    void standardBeaconRejectsInequality() {
        BeaconVersion version = BeaconVersion.of(List.of(StandardBeacon.create("foo", 24, "foo", false, 0)));
        ExprContext in = new ExprContext(
            "foo < :v", null, Map.of(":v", AttributeValue.fromN("5")), null);

        DynamoDbEncryptionTransformsException ex = assertThrows(
            DynamoDbEncryptionTransformsException.class,
            () -> QueryBeaconizer.beaconize(version, in, keysFor(version), 0));
        assertTrue(ex.getMessage().contains("standard beacon"));
    }

    @Test
    void valueUsedInTwoBeaconContextsIsRejected() {
        // foo and bar hash under distinct keys, so the same value yields two different
        // beacon values for :v, which the single-value-one-context rule forbids.
        BeaconVersion version = BeaconVersion.of(List.of(
            StandardBeacon.create("foo", 24, "foo", false, 0),
            StandardBeacon.create("bar", 24, "bar", false, 0)));
        ExprContext in = new ExprContext(
            "foo = :v OR bar = :v", null, Map.of(":v", AttributeValue.fromS("x")), null);

        DynamoDbEncryptionTransformsException ex = assertThrows(
            DynamoDbEncryptionTransformsException.class,
            () -> QueryBeaconizer.beaconize(version, in, keysFor(version), 0));
        assertTrue(ex.getMessage().contains("two different contexts"));
    }

    @Test
    void queryingAnEncryptedNonBeaconFieldIsRejected() {
        BeaconVersion version = BeaconVersion.create(
            List.of(new Beacon.Standard(StandardBeacon.create("foo", 24, "foo", false, 0))),
            Map.of(), Set.of("secret"));
        ExprContext in = new ExprContext(
            "secret = :v", null, Map.of(":v", AttributeValue.fromS("x")), null);

        DynamoDbEncryptionTransformsException ex = assertThrows(
            DynamoDbEncryptionTransformsException.class,
            () -> QueryBeaconizer.beaconize(version, in, keysFor(version), 0));
        assertTrue(ex.getMessage().contains("secret"));
    }

    @Test
    void compoundEqualityRewriteMatchesDirectBeaconValue() {
        // A compound beacon query is rewritten to aws_dbe_b_<name> and its value beaconized;
        // the result must equal CompoundBeacon.getBeaconValue for the same value, which is
        // what the stored write-path beacon equals (the equality-match property).
        StandardBeacon encBeacon = StandardBeacon.create("enc", 24, "e", false, 0, null, true);
        CompoundBeacon comp = CompoundBeacon.create("comp", '.', List.of(
            new BeaconPart.Signed("S_", "sig", TermLoc.make("s")),
            new BeaconPart.Encrypted("E_", encBeacon)), List.of());
        BeaconVersion version = BeaconVersion.create(
            List.of(new Beacon.Standard(encBeacon), new Beacon.Compound(comp)), Map.of());
        MaybeKeyMap keys = keysFor(version);
        ExprContext in = new ExprContext(
            "comp = :c", null, Map.of(":c", AttributeValue.fromS("S_foo.E_bar")), null);

        ExprContext out = QueryBeaconizer.beaconize(version, in, keys, 0);

        assertEquals("aws_dbe_b_comp = :c", out.keyExpr());
        AttributeValue expected = comp.getBeaconValue(
            AttributeValue.fromS("S_foo.E_bar"), ((MaybeKeyMap.Keys) keys).keys(), true, 0);
        assertEquals(expected, out.values().get(":c"));
    }
}
