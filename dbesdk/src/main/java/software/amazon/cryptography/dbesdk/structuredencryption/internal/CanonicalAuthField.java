package software.amazon.cryptography.dbesdk.structuredencryption.internal;

/**
 * A field in canonical form on the decrypt path, before the header legend has
 * resolved its crypto action (StructuredEncryption behavior spec §4.2, §4.7).
 * Sorted by {@code canonicalPath}, then walked against the legend to produce
 * {@link CanonicalField}s.
 */
public record CanonicalAuthField(
    byte[] canonicalPath, Path originalKey, Terminal data, AuthenticateAction action) {}
