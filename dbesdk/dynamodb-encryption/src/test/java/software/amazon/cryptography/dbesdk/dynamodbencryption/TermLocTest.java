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

class TermLocTest {

    @Test
    void parsesBareFieldNameAsSingleMapSelector() {
        assertEquals(List.of(new TermLoc.MapKey("foo")), TermLoc.make("foo").selectors());
    }

    @Test
    void parsesMapAndListSegments() {
        assertEquals(
            List.of(
                new TermLoc.MapKey("a"),
                new TermLoc.MapKey("b"),
                new TermLoc.ListIndex(3),
                new TermLoc.MapKey("c")),
            TermLoc.make("a.b[3].c").selectors());
    }

    @Test
    void rejectsEmptyLocation() {
        assertThrows(BeaconException.class, () -> TermLoc.make(""));
    }

    @Test
    void rejectsNonNumericListIndex() {
        assertThrows(BeaconException.class, () -> TermLoc.make("a[x]"));
    }

    @Test
    void rejectsUnterminatedListIndex() {
        assertThrows(BeaconException.class, () -> TermLoc.make("a[3"));
    }

    @Test
    void rejectsListIndexTooLarge() {
        assertThrows(BeaconException.class, () -> TermLoc.make("a[99999999999999999999]"));
    }

    @Test
    void locatesTopLevelAttribute() {
        Map<String, AttributeValue> item = Map.of("foo", AttributeValue.fromS("bar"));
        assertEquals(Optional.of(AttributeValue.fromS("bar")), TermLoc.make("foo").termToAttr(item));
    }

    @Test
    void absentTopLevelAttributeIsEmpty() {
        assertEquals(Optional.empty(), TermLoc.make("foo").termToAttr(Map.of()));
    }

    @Test
    void locatesNestedMapValue() {
        Map<String, AttributeValue> item =
            Map.of("a", AttributeValue.fromM(Map.of("b", AttributeValue.fromS("x"))));
        assertEquals(Optional.of(AttributeValue.fromS("x")), TermLoc.make("a.b").termToAttr(item));
    }

    @Test
    void locatesListElementByIndex() {
        Map<String, AttributeValue> item =
            Map.of("a", AttributeValue.fromL(List.of(AttributeValue.fromS("x"), AttributeValue.fromS("y"))));
        assertEquals(Optional.of(AttributeValue.fromS("y")), TermLoc.make("a[1]").termToAttr(item));
    }

    @Test
    void missingNestedKeyIsEmpty() {
        Map<String, AttributeValue> item =
            Map.of("a", AttributeValue.fromM(Map.of("b", AttributeValue.fromS("x"))));
        assertEquals(Optional.empty(), TermLoc.make("a.c").termToAttr(item));
    }

    @Test
    void outOfRangeListIndexIsEmpty() {
        Map<String, AttributeValue> item =
            Map.of("a", AttributeValue.fromL(List.of(AttributeValue.fromS("x"))));
        assertEquals(Optional.empty(), TermLoc.make("a[5]").termToAttr(item));
    }

    @Test
    void mapSelectorOnListIsEmpty() {
        Map<String, AttributeValue> item =
            Map.of("a", AttributeValue.fromL(List.of(AttributeValue.fromS("x"))));
        assertEquals(Optional.empty(), TermLoc.make("a.b").termToAttr(item));
    }

    @Test
    void listSelectorOnMapIsEmpty() {
        Map<String, AttributeValue> item =
            Map.of("a", AttributeValue.fromM(Map.of("b", AttributeValue.fromS("x"))));
        assertEquals(Optional.empty(), TermLoc.make("a[0]").termToAttr(item));
    }

    @Test
    void selectorPastScalarIsEmpty() {
        Map<String, AttributeValue> item = Map.of("a", AttributeValue.fromS("x"));
        assertEquals(Optional.empty(), TermLoc.make("a.b").termToAttr(item));
    }

    @Test
    void termToBytesSerializesLocatedValue() {
        Map<String, AttributeValue> item = Map.of("a", AttributeValue.fromN("1.23"));
        assertEquals(Optional.empty(), TermLoc.make("missing").termToBytes(item));
        Optional<byte[]> located = TermLoc.make("a").termToBytes(item);
        assertTrue(located.isPresent());
        assertArrayEquals(
            DynamoToStruct.attrToStructured(AttributeValue.fromN("1.23")).value(), located.get());
    }
}
