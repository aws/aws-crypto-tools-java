package software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms;

/**
 * Extracts the target table name from a PartiQL statement
 * (ExecuteStatement / BatchExecuteStatement / ExecuteTransaction), a faithful
 * port of the Dafny {@code DdbStatement.TableFromStatement}.
 *
 * <p>Returns {@code null} when no table name can be parsed; the caller treats
 * that as a hard failure (matching the Dafny {@code :-} propagation), so a
 * statement whose table cannot be identified is never passed through.
 *
 * <p>Table-name validity follows the documented AWS DynamoDB constraint the
 * Dafny {@code DDB.TableName} type derives from (length 3–255, characters
 * {@code [a-zA-Z0-9_.-]}); the generated submodule source was not available
 * locally to byte-confirm.
 */
final class PartiqlStatement {

    private PartiqlStatement() {
    }

    static String tableFromStatement(String statement) {
        String s = stripLeadingWhitespace(statement);
        if (s.length() > 6 && asciiLower(s.substring(0, 6)).equals("exists")) {
            return tableFromExists(s.substring(6));
        }
        int len = findTokenLen(s);
        String cmd = asciiLower(s.substring(0, len));
        String rest = s.substring(len);
        switch (cmd) {
            case "select":
                return tableFromSelect(rest);
            case "update":
                return tableFromUpdate(rest);
            case "delete":
                return tableFromDelete(rest);
            case "insert":
                return tableFromInsert(rest);
            default:
                return null;
        }
    }

    private static String tableFromExists(String statement) {
        String s = stripLeadingWhitespace(statement);
        if (s.isEmpty() || s.charAt(0) != '(') {
            return null;
        }
        s = stripLeadingWhitespace(s.substring(1));
        int len = findTokenLen(s);
        if (!asciiLower(s.substring(0, len)).equals("select")) {
            return null;
        }
        return tableFromSelect(s.substring(len));
    }

    // SELECT target is "Table" or "Table.Index"; keep only the table.
    private static String tableFromSelect(String statement) {
        String name = tableFromSelectInner(statement);
        if (name == null) {
            return null;
        }
        int dot = name.indexOf('.');
        return getTableName(dot < 0 ? name : name.substring(0, dot));
    }

    // Find the first bare "from" token, then take the following token as the table.
    private static String tableFromSelectInner(String statement) {
        String s = statement;
        while (true) {
            if (s.isEmpty()) {
                return null;
            }
            String t = stripLeadingWhitespace(s);
            int len = findTokenLen(t);
            if (asciiLower(t.substring(0, len)).equals("from")) {
                String after = stripLeadingWhitespace(t.substring(len));
                return after.substring(0, findTokenLen(after));
            }
            if (len == 0) {
                return null;
            }
            s = t.substring(len);
        }
    }

    private static String tableFromUpdate(String statement) {
        String s = stripLeadingWhitespace(statement);
        int len = findTokenLen(s);
        return len == 0 ? null : getTableName(s.substring(0, len));
    }

    private static String tableFromDelete(String statement) {
        String s = stripLeadingWhitespace(statement);
        int len = findTokenLen(s);
        if (!asciiLower(s.substring(0, len)).equals("from")) {
            return null;
        }
        s = stripLeadingWhitespace(s.substring(len));
        len = findTokenLen(s);
        return len == 0 ? null : getTableName(s.substring(0, len));
    }

    private static String tableFromInsert(String statement) {
        String s = stripLeadingWhitespace(statement);
        int len = findTokenLen(s);
        if (!asciiLower(s.substring(0, len)).equals("into")) {
            return null;
        }
        s = stripLeadingWhitespace(s.substring(len));
        len = findTokenLen(s);
        return len == 0 ? null : getTableName(s.substring(0, len));
    }

    private static String getTableName(String token) {
        String s = unQuote(token);
        return isValidTableName(s) ? s : null;
    }

    private static String unQuote(String token) {
        String s = token;
        if (!s.isEmpty() && s.charAt(0) == '"') {
            s = s.substring(1);
        }
        if (!s.isEmpty() && s.charAt(s.length() - 1) == '"') {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }

    private static boolean isValidTableName(String s) {
        if (s.length() < 3 || s.length() > 255) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            boolean ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
                || (ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '-';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    private static boolean isWhitespace(char ch) {
        return ch <= ' ';
    }

    private static String stripLeadingWhitespace(String s) {
        int i = 0;
        while (i < s.length() && isWhitespace(s.charAt(i))) {
            i++;
        }
        return s.substring(i);
    }

    // Token length: a quoted token runs to its closing quote (or end); otherwise
    // to the next whitespace. Zero if the string starts empty or with whitespace.
    private static int findTokenLen(String s) {
        if (s.isEmpty() || isWhitespace(s.charAt(0))) {
            return 0;
        }
        if (s.charAt(0) == '"') {
            return 1 + findTokenLenQuoted(s.substring(1));
        }
        int len = 0;
        while (len < s.length() && !isWhitespace(s.charAt(len))) {
            len++;
        }
        return len;
    }

    private static int findTokenLenQuoted(String s) {
        int i = 0;
        while (i < s.length() && s.charAt(i) != '"') {
            i++;
        }
        return i < s.length() ? i + 1 : i;
    }

    private static String asciiLower(String s) {
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            out.append(ch >= 'A' && ch <= 'Z' ? (char) (ch - 'A' + 'a') : ch);
        }
        return out.toString();
    }
}
