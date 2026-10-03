package software.amazon.cryptography.dbesdk.dynamodbencryption;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class NumberNormalizerTest {

    @Test
    void normalizesToCanonicalDecimal() {
        // Grounded golden cases from test/DynamoToStruct.dfy:
        assertEquals("123", NumberNormalizer.normalizeNumber("000123.000"));
        assertEquals("1", NumberNormalizer.normalizeNumber("001.00"));
        // Standard decimal normalizations:
        assertEquals("123", NumberNormalizer.normalizeNumber("123"));
        assertEquals("1.5", NumberNormalizer.normalizeNumber("1.50"));
        assertEquals("100", NumberNormalizer.normalizeNumber("100"));
        assertEquals("0", NumberNormalizer.normalizeNumber("0"));
    }

    @Test
    void foldsExponentIntoDecimalPoint() {
        assertEquals("100", NumberNormalizer.normalizeNumber("1e2"));
        assertEquals("123", NumberNormalizer.normalizeNumber("1.23e2"));
        assertEquals("0.0123", NumberNormalizer.normalizeNumber("1.23e-2"));
    }

    @Test
    void keepsSignExceptForZero() {
        assertEquals("-1.5", NumberNormalizer.normalizeNumber("-1.50"));
        assertEquals("0", NumberNormalizer.normalizeNumber("-0"));
        assertEquals("123", NumberNormalizer.normalizeNumber("+123"));
    }

    @Test
    void rejectsEmptyString() {
        DynamoToStructException thrown = assertThrows(
            DynamoToStructException.class, () -> NumberNormalizer.normalizeNumber(""));
        assertEquals("An empty string is not a valid number. when parsing ''.", thrown.getMessage());
    }

    @Test
    void rejectsNonDigitCharacter() {
        assertThrows(DynamoToStructException.class, () -> NumberNormalizer.normalizeNumber("12a3"));
    }

    @Test
    void rejectsMoreThan38SignificantDigits() {
        String thirtyNine = "1".repeat(39);
        DynamoToStructException thrown = assertThrows(
            DynamoToStructException.class, () -> NumberNormalizer.normalizeNumber(thirtyNine));
        assertEquals(
            "Attempting to store more than 38 significant digits in a Number. when parsing '" + thirtyNine + "'.",
            thrown.getMessage());
    }
}
