package software.amazon.cryptography.dbesdk.dynamodbencryption;

/**
 * Compare two numbers held as decimal strings, as the query output filter must to evaluate
 * numeric key/sort conditions (a DynamoDB Number is stored as text). A faithful port of the
 * MPL StandardLibrary {@code FloatCompare} module: it never fails — for any two strings it
 * produces an ordering — and understands sign, a decimal point, and an {@code e}/{@code E}
 * exponent, so it orders numerically rather than lexically ({@code "9" < "10"},
 * {@code "1e3" == "1000"}).
 */
public final class FloatCompare {

    static final int LESS = -1;
    static final int EQUAL = 0;
    static final int GREATER = 1;

    private FloatCompare() {}

    /** -1 if {@code x < y}, 0 if equal, 1 if {@code x > y}, comparing both as numbers. */
    public static int compareFloat(String xRaw, String yRaw) {
        String x = cleanNumber(xRaw);
        String y = cleanNumber(yRaw);
        if (isNegative(x) && isNegative(y)) {
            return compareFloatInner(y.substring(1), x.substring(1));
        }
        if (isNegative(x)) {
            return LESS;
        }
        if (isNegative(y)) {
            return GREATER;
        }
        return compareFloatInner(x, y);
    }

    // Compare two non-negative numbers by magnitude.
    private static int compareFloatInner(String x, String y) {
        Split xParts = splitExp(x);
        Split yParts = splitExp(y);
        Split xNum = splitDot(xParts.head);
        Split yNum = splitDot(yParts.head);
        String xDigits = skipLeadingZeros(xNum.head + xNum.tail);
        String yDigits = skipLeadingZeros(yNum.head + yNum.tail);
        // The value's exponent once the fractional digits are folded into it, so two numbers
        // written with different point placement still compare by true magnitude.
        int xExp = xParts.exp - xNum.tail.length();
        int yExp = yParts.exp - yNum.tail.length();
        int logX = xExp + xDigits.length();
        int logY = yExp + yDigits.length();
        if (logX > logY) {
            return GREATER;
        }
        if (logY > logX) {
            return LESS;
        }
        // Same order of magnitude: compare the digit strings, zero-padding the shorter.
        if (xDigits.length() < yDigits.length()) {
            return strCmp(appendZeros(xDigits, yDigits.length()), yDigits);
        }
        if (yDigits.length() < xDigits.length()) {
            return strCmp(xDigits, appendZeros(yDigits, xDigits.length()));
        }
        return strCmp(xDigits, yDigits);
    }

    // A string split into a leading part and either a trailing fraction (splitDot) or a
    // parsed exponent (splitExp).
    private record Split(String head, String tail, int exp) {}

    // Split off an e/E exponent; absent exponent is 0.
    private static Split splitExp(String x) {
        int e = x.indexOf('e');
        if (e < 0) {
            e = x.indexOf('E');
        }
        if (e < 0) {
            return new Split(x, "", 0);
        }
        return new Split(x.substring(0, e), "", strToInt(x.substring(e + 1)));
    }

    // Split on the decimal point into integer and fractional digit strings, dropping leading
    // zeros of the integer part and trailing zeros of the fraction.
    private static Split splitDot(String x) {
        int dot = x.indexOf('.');
        if (dot < 0) {
            return new Split(skipLeadingZeros(x), "", 0);
        }
        return new Split(skipLeadingZeros(x.substring(0, dot)), skipTrailingZeros(x.substring(dot + 1)), 0);
    }

    // Lexicographic compare by UTF-16 code unit; a shorter prefix sorts first.
    private static int strCmp(String x, String y) {
        int n = Math.min(x.length(), y.length());
        for (int i = 0; i < n; i++) {
            if (x.charAt(i) < y.charAt(i)) {
                return LESS;
            }
            if (x.charAt(i) > y.charAt(i)) {
                return GREATER;
            }
        }
        return Integer.compare(x.length(), y.length());
    }

    private static String appendZeros(String x, int newLength) {
        return x + "0".repeat(newLength - x.length());
    }

    // Base-10 parse, skipping leading whitespace (code units <= ' ') and honoring a leading
    // '-'; non-digits contribute nothing (Dafny StrToInt/StrToIntInner).
    private static int strToInt(String s) {
        String trimmed = skipLeadingSpace(s);
        if (trimmed.isEmpty()) {
            return 0;
        }
        int magnitude = strToIntInner(s);
        return trimmed.charAt(0) == '-' ? -magnitude : magnitude;
    }

    private static int strToIntInner(String s) {
        int acc = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= '0' && c <= '9') {
                acc = acc * 10 + (c - '0');
            }
        }
        return acc;
    }

    private static String skipLeadingSpace(String s) {
        int i = 0;
        while (i < s.length() && s.charAt(i) <= ' ') {
            i++;
        }
        return s.substring(i);
    }

    private static String skipLeadingZeros(String s) {
        int i = 0;
        while (i < s.length() && s.charAt(i) == '0') {
            i++;
        }
        return s.substring(i);
    }

    private static String skipTrailingZeros(String s) {
        int end = s.length();
        while (end > 0 && s.charAt(end - 1) == '0') {
            end--;
        }
        return s.substring(0, end);
    }

    private static boolean isNegative(String s) {
        return !s.isEmpty() && s.charAt(0) == '-';
    }

    private static String skipLeadingPlus(String s) {
        return !s.isEmpty() && s.charAt(0) == '+' ? s.substring(1) : s;
    }

    // A string is zero if it has no non-zero digit before any e/E (Dafny IsZero): '0'/'.'
    // are skipped, '1'-'9' means non-zero, anything else (an exponent) ends the scan as zero.
    private static boolean isZero(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '0' || c == '.') {
                continue;
            }
            return !(c >= '1' && c <= '9');
        }
        return true;
    }

    // Collapse any zero (including "-0", "0.0e5") to the canonical "0" so signed and
    // exponential zeros compare equal.
    private static String recognizeZero(String s) {
        if (isNegative(s)) {
            return isZero(s.substring(1)) ? "0" : s;
        }
        return isZero(s) ? "0" : s;
    }

    private static String cleanNumber(String s) {
        return recognizeZero(skipLeadingPlus(skipLeadingSpace(s)));
    }
}
