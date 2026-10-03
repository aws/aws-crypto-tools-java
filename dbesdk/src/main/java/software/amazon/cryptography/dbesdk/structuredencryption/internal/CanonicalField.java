package software.amazon.cryptography.dbesdk.structuredencryption.internal;

/**
 * A field paired with its canonical path, original path, and crypto action, in
 * canonical-sorted order (StructuredEncryption behavior spec §4.2, §4.6). The
 * canonical path is precomputed once and reused as both the sort key and the
 * footer canonical-field prefix; the original path is kept to reconstruct the
 * output item.
 */
public record CanonicalField(
    byte[] canonicalPath, Path originalKey, Terminal data, CryptoAction action) {}
