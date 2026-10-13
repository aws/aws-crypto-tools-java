package software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms.ExpressionTokenizer.Token;

class ExpressionEvaluatorTest {

    private static boolean eval(
            String expr, Map<String, AttributeValue> item,
            Map<String, String> names, Map<String, AttributeValue> values) {
        List<Token> rpn = ExpressionEvaluator.convertToRpn(
            ExpressionEvaluator.convertToPrefix(ExpressionTokenizer.parse(expr)));
        return ExpressionEvaluator.evalExpr(rpn, item, names, values);
    }

    @Test
    void convertToPrefixRewritesInToPrefixForm() {
        List<Token> prefix = ExpressionEvaluator.convertToPrefix(ExpressionTokenizer.parse("a IN (:x, :y)"));
        assertEquals(
            List.of("IN", "(", "a", ",", ":x", ",", ":y", ")"),
            prefix.stream().map(Token::text).toList());
    }

    @Test
    void convertToPrefixRewritesBetweenToPrefixForm() {
        List<Token> prefix = ExpressionEvaluator.convertToPrefix(ExpressionTokenizer.parse("a BETWEEN :lo AND :hi"));
        assertEquals(
            List.of("BETWEEN", "(", "a", ",", ":lo", ",", ":hi", ")"),
            prefix.stream().map(Token::text).toList());
    }

    @Test
    void convertToRpnOrdersOperandsBeforeOperators() {
        List<Token> rpn = ExpressionEvaluator.convertToRpn(
            ExpressionTokenizer.parse("a = :x AND b = :y"));
        assertEquals(
            List.of("a", ":x", "=", "b", ":y", "=", "AND"),
            rpn.stream().map(Token::text).toList());
    }

    @Test
    void equalityMatchesAndMismatches() {
        Map<String, AttributeValue> item = Map.of("a", AttributeValue.fromS("red"));
        assertTrue(eval("a = :x", item, null, Map.of(":x", AttributeValue.fromS("red"))));
        assertFalse(eval("a = :x", item, null, Map.of(":x", AttributeValue.fromS("blue"))));
    }

    @Test
    void numericComparisonIsNumericNotLexical() {
        // "10" > "9" numerically; a lexical compare would make "10" < "9" (since '1' < '9').
        Map<String, AttributeValue> item = Map.of("n", AttributeValue.fromN("10"));
        assertTrue(eval("n > :v", item, null, Map.of(":v", AttributeValue.fromN("9"))));
        assertFalse(eval("n < :v", item, null, Map.of(":v", AttributeValue.fromN("9"))));
    }

    @Test
    void andRequiresBothOrRequiresEither() {
        Map<String, AttributeValue> item = Map.of("a", AttributeValue.fromS("x"), "b", AttributeValue.fromS("y"));
        Map<String, AttributeValue> values = Map.of(":x", AttributeValue.fromS("x"), ":z", AttributeValue.fromS("z"));
        assertFalse(eval("a = :x AND b = :z", item, null, values));
        assertTrue(eval("a = :x OR b = :z", item, null, values));
    }

    @Test
    void beginsWithMatchesPrefix() {
        Map<String, AttributeValue> item = Map.of("a", AttributeValue.fromS("hello"));
        assertTrue(eval("begins_with(a, :p)", item, null, Map.of(":p", AttributeValue.fromS("he"))));
        assertFalse(eval("begins_with(a, :p)", item, null, Map.of(":p", AttributeValue.fromS("xy"))));
    }

    @Test
    void betweenIsNumericInclusive() {
        Map<String, AttributeValue> item = Map.of("n", AttributeValue.fromN("5"));
        Map<String, AttributeValue> values =
            Map.of(":lo", AttributeValue.fromN("5"), ":hi", AttributeValue.fromN("10"));
        assertTrue(eval("n BETWEEN :lo AND :hi", item, null, values));
        assertFalse(eval("n BETWEEN :lo AND :hi", Map.of("n", AttributeValue.fromN("11")), null, values));
    }

    @Test
    void inMatchesMembership() {
        Map<String, AttributeValue> item = Map.of("a", AttributeValue.fromS("g"));
        Map<String, AttributeValue> values =
            Map.of(":x", AttributeValue.fromS("f"), ":y", AttributeValue.fromS("g"));
        assertTrue(eval("a IN (:x, :y)", item, null, values));
        assertFalse(eval("a IN (:x, :y)", Map.of("a", AttributeValue.fromS("z")), null, values));
    }

    @Test
    void attributeExistsAndNotExistsReflectPresence() {
        Map<String, AttributeValue> item = Map.of("a", AttributeValue.fromS("x"));
        assertTrue(eval("attribute_exists(a)", item, null, Map.of()));
        assertFalse(eval("attribute_exists(b)", item, null, Map.of()));
        assertTrue(eval("attribute_not_exists(b)", item, null, Map.of()));
        assertFalse(eval("attribute_not_exists(a)", item, null, Map.of()));
    }

    @Test
    void indirectNameResolvesThroughNamesMap() {
        Map<String, AttributeValue> item = Map.of("realField", AttributeValue.fromS("v"));
        assertTrue(eval("#n = :x", item, Map.of("#n", "realField"), Map.of(":x", AttributeValue.fromS("v"))));
    }

    @Test
    void groupingParensDoNotOverridePrecedence() {
        // Faithful Dafny quirk: open parens are not stacked and a close pops a single
        // operator, so "(a = :x OR b = :y) AND c = :z" evaluates as
        // "a = :x OR (b = :y AND c = :z)" (AND binds tighter than OR). With a true, b and c
        // false, standard grouping ((a OR b) AND c) is false; the Dafny grouping is true.
        Map<String, AttributeValue> item =
            Map.of("a", AttributeValue.fromS("x"), "b", AttributeValue.fromS("B"), "c", AttributeValue.fromS("C"));
        Map<String, AttributeValue> values = Map.of(
            ":x", AttributeValue.fromS("x"),
            ":y", AttributeValue.fromS("y"),
            ":z", AttributeValue.fromS("z"));
        assertTrue(eval("(a = :x OR b = :y) AND c = :z", item, null, values));
    }

    @Test
    void malformedExpressionFailsWithTransformsException() {
        // A dangling operator leaves the stack malformed.
        assertThrows(DynamoDbEncryptionTransformsException.class,
            () -> eval("a = ", Map.of("a", AttributeValue.fromS("x")), null, Map.of()));
    }
}
