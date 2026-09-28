package software.amazon.cryptography.dbesdk.structuredencryption.internal;

/**
 * A single structured-data value: its raw bytes and a 2-byte type id
 * (StructuredEncryption behavior spec §1). An encrypted terminal carries the
 * reserved binary type id {@code 0xFFFF} and ciphertext bytes; a plaintext
 * terminal carries the value's real type id.
 *
 * <p>The byte arrays are held by reference, not copied — {@code value} may be a
 * large plaintext or key-bearing buffer, and this type only carries it between
 * pipeline stages.
 */
public record Terminal(byte[] value, byte[] typeId) {}
