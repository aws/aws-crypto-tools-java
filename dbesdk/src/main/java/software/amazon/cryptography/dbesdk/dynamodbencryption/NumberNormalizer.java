package software.amazon.cryptography.dbesdk.dynamodbencryption;

import java.math.BigInteger;

/**
 * DynamoDB number normalization (DynamoToStruct behavior spec §4), a faithful
 * port of {@code NormalizeNumber.dfy}. A DynamoDB Number is stored as its
 * normalized decimal string: the exponent is folded into the decimal point,
 * insignificant leading/trailing zeros are dropped, and the result is bounded to
 * 38 significant digits and DynamoDB's supported magnitude range. Zero
 * normalizes to {@code "0"} (its sign dropped); other values keep their sign.
 */
public final class NumberNormalizer {

    private static final int MAX_SIGNIFICANT_DIGITS = 38;
    private static final BigInteger MIN_EXPONENT_MAGNITUDE = BigInteger.valueOf(-129);
    private static final BigInteger MAX_EXPONENT_MAGNITUDE = BigInteger.valueOf(126);

    private NumberNormalizer() {}

    public static String normalizeNumber(String n) {
        try {
            return normalizeNumber2(n);
        } catch (InvalidNumber e) {
            throw new DynamoToStructException(e.getMessage() + " when parsing '" + n + "'.");
        }
    }

    private static final class InvalidNumber extends RuntimeException {
        InvalidNumber(String message) {
            super(message);
        }
    }

    private static String normalizeNumber2(String input) {
        if (input.isEmpty()) {
            throw new InvalidNumber("An empty string is not a valid number.");
        }
        boolean negative = false;
        String n = input;
        char first = n.charAt(0);
        if (first == '-') {
            negative = true;
            n = n.substring(1);
        } else if (first == '+') {
            n = n.substring(1);
        }
        if (n.isEmpty()) {
            throw new InvalidNumber("An empty string is not a valid number.");
        }
        String normalized = trimZerosFromValidNumber(normalizePositive(n));
        return (negative && !normalized.equals("0")) ? "-" + normalized : normalized;
    }

    // Parsed form of AAA.BBBeCCC: digits = "AAABBB", pointPos = index of the decimal
    // point within digits, exp = CCC.
    private record Parsed(String digits, int pointPos, BigInteger exp) {}

    private static String normalizePositive(String n) {
        Parsed parsed = parseNumber(n);
        String value = parsed.digits();
        int pos = parsed.pointPos();
        // Strip leading zeros before the point and trailing zeros after it.
        while (!value.isEmpty()) {
            if (value.charAt(0) == '0' && pos > 0) {
                value = value.substring(1);
                pos--;
            } else if (value.charAt(value.length() - 1) == '0' && pos < value.length()) {
                value = value.substring(0, value.length() - 1);
            } else {
                break;
            }
        }

        String digitsOfPrecision = skipAllTrailingZeros(skipLeadingZeros(value));
        if (digitsOfPrecision.length() > MAX_SIGNIFICANT_DIGITS) {
            throw new InvalidNumber("Attempting to store more than 38 significant digits in a Number.");
        }
        if (digitsOfPrecision.isEmpty()) {
            return "0";
        }

        BigInteger newPos = BigInteger.valueOf(pos).add(parsed.exp());
        BigInteger leadingZeros = BigInteger.valueOf(countZeros(value));
        if (newPos.signum() <= 0) {
            if (newPos.subtract(leadingZeros).compareTo(MIN_EXPONENT_MAGNITUDE) < 0) {
                throw new InvalidNumber("Attempting to store a number with magnitude smaller than supported range.");
            }
            return "0." + zeros(newPos.negate().intValueExact()) + value;
        } else if (newPos.compareTo(BigInteger.valueOf(value.length())) >= 0) {
            if (newPos.subtract(leadingZeros).compareTo(MAX_EXPONENT_MAGNITUDE) > 0) {
                throw new InvalidNumber("Attempting to store a number with magnitude larger than supported range.");
            }
            return value + zeros(newPos.intValueExact() - value.length());
        } else {
            int p = newPos.intValueExact();
            return value.substring(0, p) + "." + value.substring(p);
        }
    }

    private static Parsed parseNumber(String n) {
        int preDot = countDigits(n, 0);
        if (n.length() == preDot) {
            return new Parsed(n, n.length(), BigInteger.ZERO);
        }
        if (n.charAt(preDot) == '.') {
            int postDot = countDigits(n, preDot + 1);
            if (preDot + postDot == 0) {
                throw new InvalidNumber("Number needs digits either before or after the decimal point.");
            }
            int len = preDot + postDot + 1;
            String digits = n.substring(0, preDot) + n.substring(preDot + 1, len);
            if (len == n.length()) {
                return new Parsed(digits, preDot, BigInteger.ZERO);
            }
            if (isExponent(n.charAt(len))) {
                return new Parsed(digits, preDot, strToInt(n.substring(len + 1)));
            }
            throw new InvalidNumber("Invalid Character in number at '" + n.substring(len) + "'.");
        }
        if (preDot == 0) {
            throw new InvalidNumber("Number needs digits either before or after the decimal point.");
        }
        if (isExponent(n.charAt(preDot))) {
            return new Parsed(n.substring(0, preDot), preDot, strToInt(n.substring(preDot + 1)));
        }
        throw new InvalidNumber("Invalid Character in number at '" + n.substring(preDot) + "'.");
    }

    private static String trimZerosFromValidNumber(String value) {
        String n = skipLeadingZeros(value);
        return n.indexOf('.') >= 0 ? skipTrailingZeros(n) : n;
    }

    // Drop leading zeros, but never the zero immediately before a decimal point.
    private static String skipLeadingZeros(String value) {
        String s = value;
        while (s.length() > 1 && s.charAt(0) == '0' && s.charAt(1) != '.') {
            s = s.substring(1);
        }
        return s;
    }

    // Requires a decimal point; drop trailing zeros and a resulting trailing point.
    private static String skipTrailingZeros(String value) {
        String s = value;
        while (s.length() > 1 && s.charAt(s.length() - 1) == '0') {
            if (s.charAt(s.length() - 2) == '.') {
                return s.substring(0, s.length() - 2);
            }
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }

    private static String skipAllTrailingZeros(String value) {
        int end = value.length();
        while (end > 0 && value.charAt(end - 1) == '0') {
            end--;
        }
        return value.substring(0, end);
    }

    private static int countDigits(String s, int from) {
        int i = from;
        while (i < s.length() && isDecimalDigit(s.charAt(i))) {
            i++;
        }
        return i - from;
    }

    private static int countZeros(String value) {
        int i = 0;
        while (i < value.length() && value.charAt(i) == '0') {
            i++;
        }
        return i;
    }

    private static BigInteger strToInt(String s) {
        if (s.isEmpty()) {
            throw new InvalidNumber("An empty string is not a valid number.");
        }
        char first = s.charAt(0);
        if (first == '-' || first == '+') {
            if (s.length() <= 1) {
                throw new InvalidNumber("An empty string is not a valid number.");
            }
            BigInteger magnitude = strToIntInner(s.substring(1));
            return first == '-' ? magnitude.negate() : magnitude;
        }
        return strToIntInner(s);
    }

    private static BigInteger strToIntInner(String s) {
        BigInteger acc = BigInteger.ZERO;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!isDecimalDigit(c)) {
                throw new InvalidNumber("The character '" + c + "' is not a valid decimal digit.");
            }
            acc = acc.multiply(BigInteger.TEN).add(BigInteger.valueOf(c - '0'));
        }
        return acc;
    }

    private static String zeros(int n) {
        return "0".repeat(n);
    }

    private static boolean isDecimalDigit(char c) {
        return '0' <= c && c <= '9';
    }

    private static boolean isExponent(char c) {
        return c == 'e' || c == 'E';
    }
}
