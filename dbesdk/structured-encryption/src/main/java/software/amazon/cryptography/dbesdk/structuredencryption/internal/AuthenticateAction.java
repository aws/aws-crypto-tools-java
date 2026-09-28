package software.amazon.cryptography.dbesdk.structuredencryption.internal;

/** Whether a field is included in the signature (StructuredEncryption behavior spec §1). */
public enum AuthenticateAction {
    SIGN,
    DO_NOT_SIGN
}
