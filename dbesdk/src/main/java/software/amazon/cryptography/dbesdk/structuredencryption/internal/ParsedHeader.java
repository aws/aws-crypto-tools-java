package software.amazon.cryptography.dbesdk.structuredencryption.internal;

import java.util.List;
import java.util.Map;

/**
 * The header information a path/map operation parsed or produced, returned
 * alongside the structure (StructuredEncryption behavior spec §4.5). Mirrors the
 * Dafny {@code ParsedHeader}, expressed in native types so the pipeline stays
 * MPL-free: {@code algorithmSuite} stands in for the Dafny suite id, and the two
 * contexts capture the version-2 distinction — {@code storedEncryptionContext}
 * is what the header carries, {@code encryptionContext} is the full context the
 * signature was computed over (they differ only when a Required-Encryption-Context
 * CMM held some entries back).
 */
public record ParsedHeader(
    AlgorithmSuite algorithmSuite,
    List<EncryptedDataKey> encryptedDataKeys,
    Map<String, byte[]> storedEncryptionContext,
    Map<String, byte[]> encryptionContext) {}
