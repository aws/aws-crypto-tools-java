package software.amazon.cryptography.dbesdk.dynamodbitemencryptor;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthenticateAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Terminal;

/**
 * The pure (MPL-free) operations of the DynamoDbItemEncryptor: encryption-context
 * construction, crypto/authenticate schema construction, and plaintext detection
 * (DynamoDbItemEncryptor behavior spec sections 3 to 5). These are the pieces the
 * CMM-facing EncryptItem/DecryptItem seam composes with material resolution and the
 * StructuredEncryption core.
 *
 * <p>Inputs are the structured terminal map produced by
 * {@code DynamoToStruct.itemToStructured}; nothing here touches DynamoDB attribute
 * values except {@link #isPlaintextItem}, which only inspects attribute names.
 */
public final class ItemEncryptorOperations {

    private static final String TABLE_NAME_KEY = "aws-crypto-table-name";
    private static final String PARTITION_NAME_KEY = "aws-crypto-partition-name";
    private static final String SORT_NAME_KEY = "aws-crypto-sort-name";
    private static final String ATTR_PREFIX = "aws-crypto-attr.";
    private static final String HEADER_FIELD = "aws_dbe_head";
    private static final String FOOTER_FIELD = "aws_dbe_foot";

    private ItemEncryptorOperations() {}

    /**
     * The DynamoDB item base encryption context for encryption, selected by the
     * configuration version: version 2 carries only the table and key names,
     * version 1 additionally carries the encoded partition (and sort) key values.
     */
    public static Map<String, byte[]> makeEncryptionContextForEncrypt(
            ItemEncryptorConfig config, Map<String, Terminal> item) {
        return config.version() == 2 ? contextV2(config, item) : contextV1(config, item);
    }

    /**
     * The base encryption context for decryption, selected by the version byte read
     * from the stored header (not the configuration version). A version other than
     * 1 or 2 is an error.
     */
    public static Map<String, byte[]> makeEncryptionContextForDecrypt(
            ItemEncryptorConfig config, int headerVersion, Map<String, Terminal> item) {
        if (headerVersion == 2) {
            return contextV2(config, item);
        }
        if (headerVersion == 1) {
            return contextV1(config, item);
        }
        throw new DynamoDbItemEncryptorException("Header attribute has unexpected version number");
    }

    private static Map<String, byte[]> contextV1(ItemEncryptorConfig config, Map<String, Terminal> item) {
        Map<String, byte[]> context = new LinkedHashMap<>();
        context.put(TABLE_NAME_KEY, utf8(config.logicalTableName()));
        context.put(PARTITION_NAME_KEY, utf8(config.partitionKeyName()));
        context.put(
            ATTR_PREFIX + config.partitionKeyName(),
            encodeTerminal(requireKey(item, config.partitionKeyName(), "Partition key")));
        if (config.sortKeyName() != null) {
            context.put(SORT_NAME_KEY, utf8(config.sortKeyName()));
            context.put(
                ATTR_PREFIX + config.sortKeyName(),
                encodeTerminal(requireKey(item, config.sortKeyName(), "Sort key")));
        }
        return context;
    }

    private static Map<String, byte[]> contextV2(ItemEncryptorConfig config, Map<String, Terminal> item) {
        // Version 2 omits key values, but still requires the key attributes to be present.
        requireKey(item, config.partitionKeyName(), "Partition key");
        Map<String, byte[]> context = new LinkedHashMap<>();
        context.put(TABLE_NAME_KEY, utf8(config.logicalTableName()));
        context.put(PARTITION_NAME_KEY, utf8(config.partitionKeyName()));
        if (config.sortKeyName() != null) {
            requireKey(item, config.sortKeyName(), "Sort key");
            context.put(SORT_NAME_KEY, utf8(config.sortKeyName()));
        }
        return context;
    }

    /**
     * The crypto schema: each structured attribute mapped to its configured action.
     * An attribute in signature scope with no configured action is an error; an
     * attribute out of signature scope with no configured action is DO_NOTHING.
     */
    public static Map<String, CryptoAction> configToCryptoSchema(
            ItemEncryptorConfig config, Set<String> attributeNames) {
        Map<String, CryptoAction> schema = new LinkedHashMap<>();
        for (String name : attributeNames) {
            CryptoAction action = config.attributeActionsOnEncrypt().get(name);
            if (action != null) {
                schema.put(name, action);
            } else if (!config.inSignatureScope(name)) {
                schema.put(name, CryptoAction.DO_NOTHING);
            } else {
                throw new DynamoDbItemEncryptorException("No Crypto Action configured for attribute " + name);
            }
        }
        return schema;
    }

    /** The authenticate schema: SIGN for in-scope attributes, DO_NOT_SIGN otherwise. */
    public static Map<String, AuthenticateAction> configToAuthenticateSchema(
            ItemEncryptorConfig config, Set<String> attributeNames) {
        Map<String, AuthenticateAction> schema = new LinkedHashMap<>();
        for (String name : attributeNames) {
            schema.put(name, config.inSignatureScope(name) ? AuthenticateAction.SIGN : AuthenticateAction.DO_NOT_SIGN);
        }
        return schema;
    }

    /** An item is plaintext if it has neither the reserved header nor footer attribute. */
    public static boolean isPlaintextItem(Map<String, AttributeValue> item) {
        return !item.containsKey(HEADER_FIELD) && !item.containsKey(FOOTER_FIELD);
    }

    // The encryption-context value of a key attribute: base64(typeId ++ value) as bytes.
    static byte[] encodeTerminal(Terminal terminal) {
        byte[] typeId = terminal.typeId();
        byte[] value = terminal.value();
        byte[] combined = new byte[typeId.length + value.length];
        System.arraycopy(typeId, 0, combined, 0, typeId.length);
        System.arraycopy(value, 0, combined, typeId.length, value.length);
        return Base64.getEncoder().encode(combined);
    }

    private static Terminal requireKey(Map<String, Terminal> item, String keyName, String label) {
        Terminal terminal = item.get(keyName);
        if (terminal == null) {
            throw new DynamoDbItemEncryptorException(
                label + " " + keyName + " not found in Item to be encrypted or decrypted");
        }
        return terminal;
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }
}
