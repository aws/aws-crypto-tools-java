package software.amazon.cryptography.dbesdk.structuredencryption.internal;

/**
 * What a field's plaintext should have done to it (StructuredEncryption
 * behavior spec §1). Only ENCRYPT_AND_SIGN fields are encrypted; the three
 * signed actions are all included in the footer signature; DO_NOTHING fields
 * are neither encrypted nor signed.
 */
public enum CryptoAction {
    ENCRYPT_AND_SIGN,
    SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT,
    SIGN_ONLY,
    DO_NOTHING
}
