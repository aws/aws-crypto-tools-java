package software.amazon.cryptography.dbesdk.structuredencryption;

/**
 * The single error type for the StructuredEncryption module (behavior spec §3).
 * Mirrors the Dafny module's one client error: a message plus, where a lower
 * layer failed, the underlying cause. Distinct failure conditions are
 * distinguished by message (the values the spec makes wire-visible) and, for
 * failures surfaced from a cryptographic primitive, by cause.
 */
public class StructuredEncryptionException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public StructuredEncryptionException(String message) {
        super(message);
    }

    public StructuredEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
