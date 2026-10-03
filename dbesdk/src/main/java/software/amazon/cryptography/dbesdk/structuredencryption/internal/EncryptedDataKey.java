package software.amazon.cryptography.dbesdk.structuredencryption.internal;

/**
 * One encrypted data key as it appears in the header (StructuredEncryption
 * behavior spec §4.5). All three fields are length-prefixed byte strings on the
 * wire; they are opaque to this module, which only serializes and parses them.
 */
public record EncryptedDataKey(byte[] keyProviderId, byte[] keyProviderInfo, byte[] ciphertext) {}
