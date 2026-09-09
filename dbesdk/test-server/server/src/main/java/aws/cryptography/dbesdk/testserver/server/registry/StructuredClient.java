package aws.cryptography.dbesdk.testserver.server.registry;

import aws.cryptography.dbesdk.testserver.server.error.DbesdkClientException;
import java.util.Map;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.AuthenticateAction;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.StructuredDataTerminal;

/**
 * A single configured Structured Encryption client stored in the
 * {@link StructuredClientRegistry}. Wraps a real
 * {@link software.amazon.cryptography.dbencryptionsdk.structuredencryption.StructuredEncryption}
 * plus the {@code CMM} built from the client's config (see
 * {@code RealStructuredClient}).
 *
 * <p>This is the raw structured-encryption layer beneath the item encryptor: it
 * operates on a flat map of field name to {@link StructuredDataTerminal} (opaque
 * value bytes + a 2-byte type id) rather than a DynamoDB item. Both methods
 * declare {@link DbesdkClientException}: the implementation catches exceptions
 * from the DBE library and rethrows them wrapped, so the operation wrapper
 * forwards them as {@code DBESDKClientError} with the DBE message unmodified.
 */
public interface StructuredClient {

    /**
     * Encrypt a structured-data map per the given Crypto Schema.
     *
     * @param tableName the logical table name bound into the crypto context.
     * @param plaintextStructure field name → plaintext terminal.
     * @param cryptoSchema field name → Crypto Action.
     * @return field name → terminal, with ENCRYPT_AND_SIGN terminals now holding
     *     ciphertext, plus the added header/footer terminals.
     * @throws DbesdkClientException if the DBE library fails.
     */
    Map<String, StructuredDataTerminal> encryptStructure(
            String tableName,
            Map<String, StructuredDataTerminal> plaintextStructure,
            Map<String, CryptoAction> cryptoSchema)
        throws DbesdkClientException;

    /**
     * Decrypt a structured-data map produced by {@link #encryptStructure}.
     *
     * @param tableName the logical table name (must match the encrypt call).
     * @param encryptedStructure field name → encrypted terminal.
     * @param authenticateSchema field name → Authenticate Action (signature scope).
     * @return field name → recovered plaintext terminal (header/footer stripped).
     * @throws DbesdkClientException if the DBE library fails (e.g. signature).
     */
    Map<String, StructuredDataTerminal> decryptStructure(
            String tableName,
            Map<String, StructuredDataTerminal> encryptedStructure,
            Map<String, AuthenticateAction> authenticateSchema)
        throws DbesdkClientException;
}
