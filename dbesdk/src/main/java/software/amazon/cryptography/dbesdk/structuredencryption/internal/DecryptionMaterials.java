package software.amazon.cryptography.dbesdk.structuredencryption.internal;

import java.security.PublicKey;
import java.util.Map;

/**
 * Resolved decryption materials — the output of a CMM's DecryptMaterials, passed
 * to the pipeline as plain data (StructuredEncryption behavior spec §2). The
 * suite here governs all decryption crypto and may differ from the header's.
 *
 * @param symmetricSigningKey the signing key for the data key that decrypted
 * @param verificationKey the ECDSA verification key, present only for a signing suite
 */
public record DecryptionMaterials(
    byte[] plaintextDataKey,
    AlgorithmSuite algorithmSuite,
    Map<String, byte[]> encryptionContext,
    byte[] symmetricSigningKey,
    PublicKey verificationKey) {}
