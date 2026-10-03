package software.amazon.cryptography.dbesdk.structuredencryption.internal;

/**
 * The algorithm-suite facts the structured-encryption pipeline needs, resolved
 * from the MPL suite by the caller (StructuredEncryption behavior spec §2, §4).
 * Keeping this a plain descriptor keeps the crypto pipeline free of any MPL
 * dependency: the seam that owns the CMM populates these from the real suite.
 *
 * @param flavor the header format flavor byte (0x00 no-ECDSA, 0x01 ECDSA P-384)
 * @param hasEcdsaSignature whether the footer carries an ECDSA signature
 * @param keyDerivationHmac JCA Mac name for the field-root-key HKDF
 * @param commitmentHmac JCA Mac name for the commit-key HKDF and the commitment
 * @param symmetricSignatureHmac JCA Mac name for recipient tags
 * @param encryptionKeyLength field-root-key length in bytes
 * @param commitmentKeyLength commit-key length in bytes
 */
public record AlgorithmSuite(
    byte flavor,
    boolean hasEcdsaSignature,
    String keyDerivationHmac,
    String commitmentHmac,
    String symmetricSignatureHmac,
    int encryptionKeyLength,
    int commitmentKeyLength) {}
