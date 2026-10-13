package software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.util.List;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms.ExpressionTokenizer.Token;

class ExpressionTokenizerTest {

    private static List<String> texts(String expr) {
        return ExpressionTokenizer.parse(expr).stream().map(Token::text).toList();
    }

    @Test
    void classifiesAttrsValuesAndOperators() {
        List<Token> tokens = ExpressionTokenizer.parse("#a = :v AND b < :w");

        assertEquals(List.of("#a", "=", ":v", "AND", "b", "<", ":w"),
            tokens.stream().map(Token::text).toList());
        assertInstanceOf(Token.Attr.class, tokens.get(0));
        assertEquals(Token.Symbol.EQ, tokens.get(1));
        assertInstanceOf(Token.Value.class, tokens.get(2));
        assertEquals(Token.Symbol.AND, tokens.get(3));
        assertEquals(Token.Symbol.LT, tokens.get(5));
    }

    @Test
    void lexesTwoCharComparators() {
        assertEquals(List.of("x", "<=", "y", ">=", "z", "<>", "w"), texts("x <= y >= z <> w"));
    }

    @Test
    void keywordMatchingHasNoWordBoundary() {
        // "info" lexes as IN then the attribute "fo" — the deliberate Dafny PrefixLower quirk.
        List<Token> tokens = ExpressionTokenizer.parse("info");
        assertEquals(Token.Symbol.IN, tokens.get(0));
        assertEquals("fo", tokens.get(1).text());
        assertInstanceOf(Token.Attr.class, tokens.get(1));
    }

    @Test
    void lexesSpecialFunctionsAndPunctuation() {
        List<Token> tokens = ExpressionTokenizer.parse("attribute_exists(#a)");
        assertEquals(Token.Symbol.ATTRIBUTE_EXISTS, tokens.get(0));
        assertEquals(Token.Symbol.OPEN, tokens.get(1));
        assertInstanceOf(Token.Attr.class, tokens.get(2));
        assertEquals(Token.Symbol.CLOSE, tokens.get(3));
    }

    @Test
    void toExpressionRejoinsOnSingleSpaces() {
        assertEquals("#a = :v", ExpressionTokenizer.toExpression(ExpressionTokenizer.parse("#a=:v")));
    }
}
