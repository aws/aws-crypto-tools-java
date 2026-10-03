package software.amazon.cryptography.dbesdk.structuredencryption.internal;

import java.security.PrivateKey;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Resolved encryption materials — the output of a CMM's GetEncryptionMaterials,
 * passed to the pipeline as plain data so the pipeline needs no MPL dependency
 * (StructuredEncryption behavior spec §2). The full {@code encryptionContext} is
 * the footer AAD; the header stores it minus {@code requiredEncryptionContextKeys}.
 *
 * @param symmetricSigningKeys one per encrypted data key, in the same order
 * @param signingKey the ECDSA signing key, present only for a signing suite
 */
public record EncryptionMaterials(
    byte[] plaintextDataKey,
    AlgorithmSuite algorithmSuite,
    List<EncryptedDataKey> encryptedDataKeys,
    Map<String, byte[]> encryptionContext,
    Set<String> requiredEncryptionContextKeys,
    List<byte[]> symmetricSigningKeys,
    PrivateKey signingKey) {}
