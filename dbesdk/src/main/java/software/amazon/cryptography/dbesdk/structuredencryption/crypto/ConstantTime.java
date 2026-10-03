package software.amazon.cryptography.dbesdk.structuredencryption.crypto;

/**
 * Constant-time byte-array equality (StructuredEncryption behavior spec §4.9).
 * Used where a timing side channel would leak secret-dependent information —
 * header commitment verification and recipient-tag comparison. The comparison
 * accumulates differences over every byte rather than returning early.
 */
public final class ConstantTime {

    private ConstantTime() {}

    public static boolean equals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int difference = 0;
        for (int i = 0; i < a.length; i++) {
            difference |= a[i] ^ b[i];
        }
        return difference == 0;
    }
}
