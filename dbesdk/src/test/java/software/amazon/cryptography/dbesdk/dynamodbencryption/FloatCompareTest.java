package software.amazon.cryptography.dbesdk.dynamodbencryption;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class FloatCompareTest {

    @Test
    void ordersByMagnitudeNotLexically() {
        // Lexically "10" < "9"; numerically "10" > "9".
        assertTrue(FloatCompare.compareFloat("10", "9") > 0);
        assertTrue(FloatCompare.compareFloat("9", "10") < 0);
    }

    @Test
    void equalValuesCompareEqualAcrossForms() {
        assertTrue(FloatCompare.compareFloat("5", "5") == 0);
        assertTrue(FloatCompare.compareFloat("0.5", "0.50") == 0);
        assertTrue(FloatCompare.compareFloat("1e3", "1000") == 0);
    }

    @Test
    void negativeIsLessThanPositiveAndMoreNegativeIsLess() {
        assertTrue(FloatCompare.compareFloat("-5", "3") < 0);
        assertTrue(FloatCompare.compareFloat("-5", "-3") < 0);
    }

    @Test
    void signedAndExponentialZerosAreEqual() {
        assertTrue(FloatCompare.compareFloat("-0", "0") == 0);
        assertTrue(FloatCompare.compareFloat("0.0", "0") == 0);
    }
}
