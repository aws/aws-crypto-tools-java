package software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms;

import java.util.ArrayList;
import java.util.List;
import software.amazon.cryptography.dbesdk.dynamodbencryption.TermLoc;

/**
 * The parsed-token model and tokenizer for DynamoDB condition / key-condition expressions,
 * a faithful port of {@code DynamoDBFilterExpr}'s {@code Token} datatype and
 * {@code ParseExpr}/{@code FindIndexToken}. Shared by condition-attribute extraction
 * (Layer A, {@link ConditionExpressionParser}) and the beacon query rewrite (B2).
 *
 * <p>Keyword matching deliberately does not require a word boundary (Dafny {@code PrefixLower}
 * does not), so a token beginning with a keyword's letters is lexed as that keyword
 * (e.g. {@code info} lexes as {@code IN} then {@code fo}). This quirk is replicated exactly
 * for behavioral parity.
 */
final class ExpressionTokenizer {

    private ExpressionTokenizer() {
    }

    /** One parsed token (Dafny {@code Token}). */
    sealed interface Token permits Token.Attr, Token.Value, Token.Symbol {
        /** The token's source text (Dafny {@code TokenToString}). */
        String text();

        /** An attribute reference: a bare name, a {@code #name} placeholder, or a document path. */
        record Attr(String s, TermLoc loc) implements Token {
            @Override public String text() {
                return s;
            }
        }

        /** A {@code :value} placeholder into {@code ExpressionAttributeValues}. */
        record Value(String s) implements Token {
            @Override public String text() {
                return s;
            }
        }

        /** An operator, keyword, or punctuation token. */
        enum Symbol implements Token {
            EQ("="), NE("<>"), LT("<"), GT(">"), LE("<="), GE(">="),
            BETWEEN("BETWEEN"), IN("IN"), OPEN("("), CLOSE(")"), COMMA(","),
            NOT("NOT"), AND("AND"), OR("OR"),
            ATTRIBUTE_EXISTS("attribute_exists"), ATTRIBUTE_NOT_EXISTS("attribute_not_exists"),
            ATTRIBUTE_TYPE("attribute_type"), BEGINS_WITH("begins_with"),
            CONTAINS("contains"), SIZE("size");

            private final String text;

            Symbol(String text) {
                this.text = text;
            }

            @Override public String text() {
                return text;
            }
        }
    }

    /** Tokenize an expression (Dafny {@code ParseExpr}); an unrecognized character ends parsing. */
    static List<Token> parse(String expr) {
        List<Token> tokens = new ArrayList<>();
        int pos = 0;
        while (pos < expr.length()) {
            Lexed lexed = findIndexToken(expr, pos);
            if (lexed.len <= 0) {
                break;
            }
            tokens.add(lexed.token);
            pos += lexed.len;
        }
        return tokens;
    }

    /** Rebuild an expression from tokens, joined with single spaces (Dafny {@code ParsedExprToString}). */
    static String toExpression(List<Token> tokens) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < tokens.size(); i++) {
            if (i > 0) {
                out.append(' ');
            }
            out.append(tokens.get(i).text());
        }
        return out.toString();
    }

    private record Lexed(int len, Token token) {
    }

    // The next token and the characters it consumes (Dafny FindIndexToken). A zero length
    // means "stop" (end of input or an unrecognized character).
    private static Lexed findIndexToken(String s, int pos) {
        int n = s.length();
        char ch = s.charAt(pos);
        int remaining = n - pos;
        if (ch == ' ') {
            Lexed next = pos + 1 < n ? findIndexToken(s, pos + 1) : stop();
            return next.len == 0 ? next : new Lexed(next.len + 1, next.token);
        }
        if (ch == '(') {
            return new Lexed(1, Token.Symbol.OPEN);
        }
        if (ch == ')') {
            return new Lexed(1, Token.Symbol.CLOSE);
        }
        if (ch == ',') {
            return new Lexed(1, Token.Symbol.COMMA);
        }
        if (ch == '=') {
            return new Lexed(1, Token.Symbol.EQ);
        }
        if (ch == '<') {
            if (remaining == 1) {
                return new Lexed(1, Token.Symbol.LT);
            }
            char next = s.charAt(pos + 1);
            if (next == '=') {
                return new Lexed(2, Token.Symbol.LE);
            }
            return next == '>' ? new Lexed(2, Token.Symbol.NE) : new Lexed(1, Token.Symbol.LT);
        }
        if (ch == '>') {
            if (remaining == 1) {
                return new Lexed(1, Token.Symbol.GT);
            }
            return s.charAt(pos + 1) == '=' ? new Lexed(2, Token.Symbol.GE) : new Lexed(1, Token.Symbol.GT);
        }
        if (prefixLower("in", s, pos)) {
            return new Lexed(2, Token.Symbol.IN);
        }
        if (prefixLower("between", s, pos)) {
            return new Lexed(7, Token.Symbol.BETWEEN);
        }
        if (prefixLower("and", s, pos)) {
            return new Lexed(3, Token.Symbol.AND);
        }
        if (prefixLower("or", s, pos)) {
            return new Lexed(2, Token.Symbol.OR);
        }
        if (prefixLower("not", s, pos)) {
            return new Lexed(3, Token.Symbol.NOT);
        }
        if (prefixLower("attribute_not_exists", s, pos)) {
            return new Lexed(20, Token.Symbol.ATTRIBUTE_NOT_EXISTS);
        }
        if (prefixLower("attribute_type", s, pos)) {
            return new Lexed(14, Token.Symbol.ATTRIBUTE_TYPE);
        }
        if (prefixLower("begins_with", s, pos)) {
            return new Lexed(11, Token.Symbol.BEGINS_WITH);
        }
        if (prefixLower("attribute_exists", s, pos)) {
            return new Lexed(16, Token.Symbol.ATTRIBUTE_EXISTS);
        }
        if (prefixLower("contains", s, pos)) {
            return new Lexed(8, Token.Symbol.CONTAINS);
        }
        if (prefixLower("size", s, pos)) {
            return new Lexed(4, Token.Symbol.SIZE);
        }
        if (ch == ':') {
            int len = valueLen(s, pos + 1) + 1;
            return new Lexed(len, new Token.Value(s.substring(pos, pos + len)));
        }
        if (ch == '#') {
            int len = valueLen(s, pos + 1) + 1;
            return new Lexed(len, makeAttr(s.substring(pos, pos + len)));
        }
        int len = attributeLen(s, pos);
        if (len == 0) {
            return stop();
        }
        return new Lexed(len, makeAttr(s.substring(pos, pos + len)));
    }

    private static Lexed stop() {
        return new Lexed(0, Token.Symbol.CLOSE);
    }

    // An attribute token's location (Dafny MakeAttr): the parsed document path, or a single
    // map key when the text is not a parseable path (e.g. a #name placeholder).
    private static Token makeAttr(String s) {
        try {
            return new Token.Attr(s, TermLoc.make(s));
        } catch (RuntimeException parseFailure) {
            return new Token.Attr(s, TermLoc.ofKey(s));
        }
    }

    // Matches the fixed, already-lowercase keyword against s[pos..], lowercasing only ASCII
    // A-Z (Dafny CharLower), with no trailing word boundary.
    private static boolean prefixLower(String keyword, String s, int pos) {
        if (pos + keyword.length() > s.length()) {
            return false;
        }
        for (int i = 0; i < keyword.length(); i++) {
            if (keyword.charAt(i) != asciiLower(s.charAt(pos + i))) {
                return false;
            }
        }
        return true;
    }

    private static char asciiLower(char ch) {
        return (ch >= 'A' && ch <= 'Z') ? (char) (ch - 'A' + 'a') : ch;
    }

    private static boolean valueChar(char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_';
    }

    private static boolean attributeChar(char ch) {
        return valueChar(ch) || ch == ':' || ch == '[' || ch == ']' || ch == '.' || ch == '#';
    }

    private static int valueLen(String s, int pos) {
        int len = 0;
        while (pos + len < s.length() && valueChar(s.charAt(pos + len))) {
            len++;
        }
        return len;
    }

    private static int attributeLen(String s, int pos) {
        int len = 0;
        while (pos + len < s.length() && attributeChar(s.charAt(pos + len))) {
            len++;
        }
        return len;
    }
}
