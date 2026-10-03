package software.amazon.cryptography.dbesdk.structuredencryption.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Path;

class CanonicalPathComparatorTest {

    private final CanonicalPathComparator comparator = new CanonicalPathComparator();

    /**
     * Reproduces {@code test/Header.dfy} TestSchemaOrderLength: keys sort
     * length-major (shorter UTF-8 key first, then by content among equal
     * lengths), because the canonical path encodes the key length before the
     * key bytes. Sorting by attribute name directly would give aa, aaa, aaaa,
     * zz, zzz, zzzz — the wrong order.
     */
    @Test
    void ordersLengthMajorLikeDafny() {
        List<String> keys = new ArrayList<>(List.of("zzzz", "aa", "aaaa", "zz", "aaa", "zzz"));

        keys.sort(Comparator.comparing(
            key -> CanonicalPath.canonicalPath("example_table", Path.ofAttribute(key)),
            comparator));

        assertEquals(List.of("aa", "zz", "aaa", "zzz", "aaaa", "zzzz"), keys);
    }

    /**
     * A byte ≥ 0x80 must sort after 0x00. A signed comparison (Byte.compare or
     * b1 - b2) would treat 0x80 as -128 and place it first, so this fails for
     * the signed-byte mistake the comparator exists to avoid.
     */
    @Test
    void comparesBytesUnsigned() {
        assertTrue(comparator.compare(new byte[] {(byte) 0x80}, new byte[] {0x00}) > 0);
    }
}
