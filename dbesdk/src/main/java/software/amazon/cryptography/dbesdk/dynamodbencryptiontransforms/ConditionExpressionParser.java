package software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms.ExpressionTokenizer.Token;

/**
 * Extracts the attribute names referenced in a DynamoDB condition / key-condition
 * expression, resolving {@code #name} placeholders. A faithful port of the Dafny
 * {@code DynamoDBFilterExpr.ExtractAttributes} path over {@link ExpressionTokenizer}'s tokens.
 *
 * <p>Only attributes whose <em>value</em> participates are returned: the operand of
 * {@code attribute_exists} / {@code attribute_not_exists} / {@code size} is skipped, matching
 * the Dafny extractor ({@code IsSpecial}), because those functions do not read the attribute's
 * value.
 */
final class ConditionExpressionParser {

    private ConditionExpressionParser() {
    }

    static List<String> extractAttributes(String expr, Map<String, String> names) {
        List<Token> tokens = ExpressionTokenizer.parse(expr);
        List<String> out = new ArrayList<>();
        int tokensUntilSkip = -1;
        for (Token t : tokens) {
            if (isSpecial(t)) {
                tokensUntilSkip = 1;
            } else if (t instanceof Token.Attr && tokensUntilSkip == 0) {
                tokensUntilSkip = -1;
            } else if (t instanceof Token.Attr attr) {
                out.add(resolve(attr.s(), names));
                tokensUntilSkip = -1;
            } else {
                tokensUntilSkip = tokensUntilSkip - 1;
            }
        }
        return out;
    }

    // The functions that ignore their operand's value (Dafny IsSpecial).
    private static boolean isSpecial(Token t) {
        return t == Token.Symbol.ATTRIBUTE_EXISTS
            || t == Token.Symbol.ATTRIBUTE_NOT_EXISTS
            || t == Token.Symbol.SIZE;
    }

    private static String resolve(String token, Map<String, String> names) {
        if (names != null && names.containsKey(token)) {
            return names.get(token);
        }
        return token;
    }
}
