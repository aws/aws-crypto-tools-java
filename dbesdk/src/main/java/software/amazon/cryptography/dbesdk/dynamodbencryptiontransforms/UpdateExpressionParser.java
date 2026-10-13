package software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Extracts the root attribute names referenced in a DynamoDB update expression,
 * resolving {@code #name} placeholders. A faithful port of the Dafny
 * {@code DynamoDbUpdateExpr.ExtractAttributes} path.
 *
 * <p>Each found name is chopped to its root attribute (before the first
 * {@code .} or {@code [}); the SET / REMOVE / ADD / DELETE clause keywords and
 * the {@code list_append} / {@code if_not_exists} functions are ignored.
 */
final class UpdateExpressionParser {

    private static final Set<String> IGNORED =
        Set.of("SET", "REMOVE", "ADD", "DELETE", "list_append", "if_not_exists");

    private UpdateExpressionParser() {
    }

    static List<String> extractAttributes(String expr, Map<String, String> names) {
        List<String> raw = extractAttrs(expr);
        if (names == null) {
            return raw;
        }
        List<String> resolved = new ArrayList<>(raw.size());
        for (String name : raw) {
            resolved.add(names.getOrDefault(name, name));
        }
        return resolved;
    }

    private static List<String> extractAttrs(String s) {
        List<String> out = new ArrayList<>();
        int pos = 0;
        while (pos < s.length()) {
            Token token = findToken(s, pos);
            if (token.len == 0) {
                break;
            }
            if (token.name != null && !IGNORED.contains(token.name)) {
                out.add(chop(token.name));
            }
            pos += token.len;
        }
        return out;
    }

    private static final class Token {
        final int len;
        final String name; // null when the token is not an attribute candidate

        Token(int len, String name) {
            this.len = len;
            this.name = name;
        }
    }

    private static Token findToken(String s, int pos) {
        char ch = s.charAt(pos);
        if (ch == '#') {
            int x = attrLen(s, pos + 1) + 1;
            return new Token(x, s.substring(pos, pos + x));
        }
        if (badStart(ch)) {
            int x = attrLen(s, pos + 1) + 1;
            return new Token(x, null);
        }
        if (attrStart(ch)) {
            int x = attrLen(s, pos + 1) + 1;
            return new Token(x, s.substring(pos, pos + x));
        }
        return new Token(1, null);
    }

    // Root attribute: the part before the first '.' or '['.
    private static String chop(String s) {
        return chopOne(chopOne(s, '.'), '[');
    }

    private static String chopOne(String s, char ch) {
        int idx = s.indexOf(ch);
        return idx < 0 ? s : s.substring(0, idx);
    }

    private static boolean badStart(char ch) {
        return ch == ':' || (ch >= '0' && ch <= '9');
    }

    private static boolean attrStart(char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '#' || ch == '_';
    }

    private static boolean attrChar(char ch) {
        return attrStart(ch) || (ch >= '0' && ch <= '9') || ch == '[' || ch == ']' || ch == '.';
    }

    private static int attrLen(String s, int pos) {
        int len = 0;
        while (pos + len < s.length() && attrChar(s.charAt(pos + len))) {
            len++;
        }
        return len;
    }
}
