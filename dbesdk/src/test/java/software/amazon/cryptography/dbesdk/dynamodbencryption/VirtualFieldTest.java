package software.amazon.cryptography.dbesdk.dynamodbencryption;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

class VirtualFieldTest {

    @Test
    void prefixSuffixHandleNegativeLengths() {
        assertEquals("hel", new VirtualTransform.Prefix(3).apply("hello"));
        assertEquals("hell", new VirtualTransform.Prefix(-1).apply("hello"));
        assertEquals("lo", new VirtualTransform.Suffix(2).apply("hello"));
        assertEquals("ello", new VirtualTransform.Suffix(-1).apply("hello"));
        assertEquals("", new VirtualTransform.Prefix(-9).apply("hi"));
    }

    @Test
    void substringUsesPositionalIndexing() {
        assertEquals("ell", new VirtualTransform.Substring(1, 4).apply("hello"));
        assertEquals("l", new VirtualTransform.Substring(-2, 5).apply("hello"));
        assertEquals("", new VirtualTransform.Substring(3, 1).apply("hello"));
    }

    @Test
    void segmentAndSegmentsSplitOnChar() {
        assertEquals("b", new VirtualTransform.Segment('.', 1).apply("a.b.c"));
        assertEquals("c", new VirtualTransform.Segment('.', -1).apply("a.b.c"));
        assertEquals("", new VirtualTransform.Segment('.', 9).apply("a.b.c"));
        assertEquals("a.b", new VirtualTransform.Segments('.', 0, 2).apply("a.b.c"));
    }

    @Test
    void segmentKeepsEmptyPieces() {
        assertEquals("", new VirtualTransform.Segment('.', 1).apply("a..b"));
    }

    @Test
    void getValueConcatenatesTransformedParts() {
        VirtualField field = VirtualField.create("v", List.of(
            new VirtualField.Part(TermLoc.make("a"),
                List.of(new VirtualTransform.Upper(), new VirtualTransform.Insert("-"))),
            new VirtualField.Part(TermLoc.make("b"), List.of())));
        Map<String, AttributeValue> item =
            Map.of("a", AttributeValue.fromS("foo"), "b", AttributeValue.fromS("bar"));
        assertEquals(Optional.of("FOO-bar"), field.getValue(item));
    }

    @Test
    void getValueAbsentWhenAnyPartMissing() {
        VirtualField field = VirtualField.create("v", List.of(
            new VirtualField.Part(TermLoc.make("a"), List.of()),
            new VirtualField.Part(TermLoc.make("b"), List.of())));
        assertTrue(field.getValue(Map.of("a", AttributeValue.fromS("foo"))).isEmpty());
    }

    @Test
    void getValueAbsentWhenPartNotString() {
        VirtualField field = VirtualField.create("v", List.of(
            new VirtualField.Part(TermLoc.make("a"), List.of())));
        assertTrue(field.getValue(Map.of("a", AttributeValue.fromN("5"))).isEmpty());
    }
}
