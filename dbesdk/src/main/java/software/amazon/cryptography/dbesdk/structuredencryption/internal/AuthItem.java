package software.amazon.cryptography.dbesdk.structuredencryption.internal;

/**
 * A field to decrypt: its path, value, and authenticate action
 * (StructuredEncryption behavior spec §1). The caller only states SIGN vs
 * DO_NOT_SIGN; the actual crypto action is recovered from the header legend.
 */
public record AuthItem(Path key, Terminal data, AuthenticateAction action) {}
