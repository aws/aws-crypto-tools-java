package software.amazon.cryptography.dbesdk.structuredencryption.crypto;

import java.util.Arrays;
import java.util.Comparator;

/**
 * Orders fields by their canonical-path bytes (StructuredEncryption behavior
 * spec §4.2). This single ordering fixes three things at once: the per-field
 * AES-CTR key offset, the footer canonical-content order, and the legend↔field
 * correspondence on decrypt.
 *
 * <p>The comparison is unsigned and byte-lexicographic. Because each canonical
 * segment encodes an 8-byte big-endian key length before the key bytes, the
 * result is length-major: a shorter UTF-8 key sorts before a longer one, and
 * only equal-length keys are ordered by content. {@link Arrays#compareUnsigned}
 * gives exactly this, including the prefix rule (a shorter array that is a
 * prefix of a longer one sorts first). A signed comparison would place any byte
 * ≥ 0x80 before 0x00, corrupting the order for the UTF-8 and length bytes that
 * routinely exceed 0x7F.
 */
public final class CanonicalPathComparator implements Comparator<byte[]> {

    @Override
    public int compare(byte[] a, byte[] b) {
        return Arrays.compareUnsigned(a, b);
    }
}
