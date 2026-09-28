package software.amazon.cryptography.dbesdk.structuredencryption.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Path;

class CanonicalPathTest {

    /**
     * The exact golden vector from {@code test/Paths.dfy} TestSpecExamples:
     * CanonPath("example_table", ["name"]). The expected bytes are the literal
     * Dafny values, not a reconstruction, so a bug in the construction logic
     * cannot make this pass.
     */
    @Test
    void matchesDafnyPathsVector() {
        byte[] expected = {
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x5f, 0x74, 0x61, 0x62, 0x6c, 0x65, // "example_table"
            0, 0, 0, 0, 0, 0, 0, 1,   // depth = 1
            0x24,                     // '$' map-segment marker
            0, 0, 0, 0, 0, 0, 0, 4,   // len(UTF8("name")) = 4
            0x6e, 0x61, 0x6d, 0x65    // "name"
        };

        byte[] actual =
            CanonicalPath.canonicalPath("example_table", Path.ofAttribute("name"));

        assertArrayEquals(expected, actual);
    }

    /**
     * A BMP non-ASCII key: the length prefix is the UTF-16 code-unit count (1),
     * not the UTF-8 byte length (2). This is the case the byte-length mistake got
     * wrong — every ASCII vector passes under both readings.
     */
    @Test
    void bmpKeyLengthIsCharCountNotByteCount() {
        String eAcute = new String(Character.toChars(0x00E9)); // "é": 1 char, 2 UTF-8 bytes

        byte[] expected = {
            0x74,                     // "t"
            0, 0, 0, 0, 0, 0, 0, 1,   // depth = 1
            0x24,                     // '$'
            0, 0, 0, 0, 0, 0, 0, 1,   // key length = 1 UTF-16 unit
            (byte) 0xc3, (byte) 0xa9  // UTF-8 of U+00E9
        };

        assertArrayEquals(expected, CanonicalPath.canonicalPath("t", Path.ofAttribute(eAcute)));
    }

    /**
     * A supplementary-plane key distinguishes UTF-16 code units from code points:
     * the DB-ESDK builds without /unicodeChar, so the length is the UTF-16 unit
     * count (2, a surrogate pair) — not the code-point count (1) or byte length (4).
     */
    @Test
    void supplementaryKeyLengthIsUtf16UnitCount() {
        String grinningFace = new String(Character.toChars(0x1F600)); // "😀": 2 UTF-16 units, 4 UTF-8 bytes

        byte[] expected = {
            0x74,                     // "t"
            0, 0, 0, 0, 0, 0, 0, 1,   // depth = 1
            0x24,                     // '$'
            0, 0, 0, 0, 0, 0, 0, 2,   // key length = 2 UTF-16 units
            (byte) 0xf0, (byte) 0x9f, (byte) 0x98, (byte) 0x80 // UTF-8 of U+1F600
        };

        assertArrayEquals(expected, CanonicalPath.canonicalPath("t", Path.ofAttribute(grinningFace)));
    }
}
