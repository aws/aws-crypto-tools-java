package software.amazon.cryptography.dbesdk.structuredencryption.internal;

/** A field to encrypt: its path, value, and crypto action (StructuredEncryption behavior spec §1). */
public record CryptoItem(Path key, Terminal data, CryptoAction action) {}
