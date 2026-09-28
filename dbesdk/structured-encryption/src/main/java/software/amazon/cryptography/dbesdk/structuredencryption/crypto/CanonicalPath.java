package software.amazon.cryptography.dbesdk.structuredencryption.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Path;

/**
 * Computes the canonical path bytes for a terminal. These bytes are used in two
 * load-bearing places (StructuredEncryption behavior spec §4.1, §4.2): as the
 * AES-GCM AAD when a field is encrypted, and as the sort key that fixes field
 * ordering. A port that produces different bytes cannot decrypt Dafny-written
 * data even if every other step is correct.
 *
 * <p>Layout: {@code UTF8(tableName) ++ uint64_be(depth) ++ perSegment(0x24 ++
 * uint64_be(charCount(key)) ++ UTF8(key))}, where depth is the number of path
 * segments and charCount is the key's UTF-16 code-unit count (the DB-ESDK Dafny
 * builds without {@code /unicodeChar}, so a Dafny string's length is its UTF-16
 * code-unit count — Java's {@code String.length()} — not its UTF-8 byte length).
 * Confirmed byte-for-byte against {@code test/Paths.dfy}.
 */
public final class CanonicalPath {

    // '$' marks a map-member segment. '#' (list index) is reserved but unused,
    // since only flat maps are supported today (behavior spec §4.1, §5).
    private static final byte MAP_SEGMENT_MARKER = 0x24;

    private CanonicalPath() {}

    public static byte[] canonicalPath(String tableName, Path path) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBytes(out, tableName.getBytes(StandardCharsets.UTF_8));
        writeUint64Be(out, path.segments().size());
        for (String segment : path.segments()) {
            out.write(MAP_SEGMENT_MARKER);
            // The length prefix is the key's UTF-16 code-unit count (matching the
            // Dafny char-sequence length), while the key itself is UTF-8 encoded.
            // These differ for any non-ASCII key.
            writeUint64Be(out, segment.length());
            writeBytes(out, segment.getBytes(StandardCharsets.UTF_8));
        }
        return out.toByteArray();
    }

    private static void writeBytes(ByteArrayOutputStream out, byte[] bytes) {
        out.write(bytes, 0, bytes.length);
    }

    private static void writeUint64Be(ByteArrayOutputStream out, long value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            out.write((int) (value >>> shift) & 0xFF);
        }
    }
}
