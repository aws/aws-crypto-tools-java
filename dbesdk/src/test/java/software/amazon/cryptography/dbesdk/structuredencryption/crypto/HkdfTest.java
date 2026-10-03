package software.amazon.cryptography.dbesdk.structuredencryption.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;

/**
 * HKDF is validated against the RFC 5869 Appendix A vectors, transcribed from
 * the MPL's own TestHKDF_Rfc5869TestVectors.dfy: A.1 (SHA-256, with salt) and
 * A.3 (SHA-256, no salt — the branch the DB-ESDK actually uses). The DB-ESDK's
 * KDF uses SHA-384/512, but the extract-then-expand construction under test is
 * hash-agnostic, and these are the authoritative in-repo known-answer vectors.
 */
class HkdfTest {

    @Test
    void matchesRfc5869CaseA1WithSalt() {
        byte[] ikm = fill((byte) 11, 22);
        byte[] salt = bytes(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12);
        byte[] info = bytes(240, 241, 242, 243, 244, 245, 246, 247, 248, 249);
        byte[] expectedOkm = bytes(
            60, 178, 95, 37, 250, 172, 213, 122, 144, 67, 79, 100, 208, 54, 47, 42, 45, 45, 10, 144,
            207, 26, 90, 76, 93, 176, 45, 86, 236, 196, 197, 191, 52, 0, 114, 8, 213, 184, 135, 24,
            88, 101);

        assertArrayEquals(expectedOkm, Hkdf.deriveKey("HmacSHA256", salt, ikm, info, 42));
    }

    @Test
    void matchesRfc5869CaseA3WithoutSalt() {
        byte[] ikm = fill((byte) 11, 22);
        byte[] expectedOkm = bytes(
            141, 164, 231, 117, 165, 99, 193, 143, 113, 95, 128, 42, 6, 60, 90, 49, 184, 161, 31, 92,
            94, 225, 135, 158, 195, 69, 78, 95, 60, 115, 141, 45, 157, 32, 19, 149, 250, 164, 182, 26,
            150, 200);

        assertArrayEquals(expectedOkm, Hkdf.deriveKey("HmacSHA256", null, ikm, new byte[0], 42));
    }

    private static byte[] fill(byte value, int length) {
        byte[] out = new byte[length];
        java.util.Arrays.fill(out, value);
        return out;
    }

    private static byte[] bytes(int... values) {
        byte[] out = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            out[i] = (byte) values[i];
        }
        return out;
    }
}
