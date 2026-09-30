package aws.cryptography.dbesdk.testserver.server.registry;

import aws.cryptography.dbesdk.testserver.server.error.DbesdkClientException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbesdk.dynamodbencryption.DynamoToStruct;
import software.amazon.cryptography.dbesdk.dynamodbitemencryptor.DynamoDbItemEncryptorException;
import software.amazon.cryptography.dbesdk.dynamodbitemencryptor.ItemEncryptorConfig;
import software.amazon.cryptography.dbesdk.dynamodbitemencryptor.ItemEncryptorOperations;
import software.amazon.cryptography.dbesdk.dynamodbitemencryptor.PlaintextOverride;
import software.amazon.cryptography.dbesdk.structuredencryption.MapStructureOutput;
import software.amazon.cryptography.dbesdk.structuredencryption.StructuredEncryptionClient;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthItem;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthenticateAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoItem;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.DecryptionMaterials;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.EncryptionMaterials;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Path;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Terminal;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.DBEAlgorithmSuiteId;

/**
 * A {@link DbesdkClient} backed by the native (non-Dafny) DynamoDbItemEncryptor.
 * It composes the MPL-free item-encryptor core ({@link ItemEncryptorOperations},
 * {@link ItemEncryptorConfig}, {@link DynamoToStruct}) with the native
 * StructuredEncryption crypto core and {@link NativeMaterialResolver} for the
 * CMM-to-materials step. Legacy overrides are not supported on this pass (the
 * factory rejects them), so encrypt/decrypt only route on the plaintext policy.
 *
 * <p>Every failure is wrapped in {@link DbesdkClientException} so the operation
 * wrapper surfaces it as {@code DBESDKClientError} with the message unmodified.
 */
public final class NativeItemEncryptorClient implements DbesdkClient {

    private static final String HEADER_FIELD = "aws_dbe_head";

    private final ItemEncryptorConfig config;
    private final DBEAlgorithmSuiteId algorithmSuiteId; // null when unset
    private final NativeMaterialResolver resolver;

    public NativeItemEncryptorClient(
            ItemEncryptorConfig config,
            DBEAlgorithmSuiteId algorithmSuiteId,
            MaterialProviders materialProviders,
            ICryptographicMaterialsManager cmm) {
        this.config = config;
        this.algorithmSuiteId = algorithmSuiteId;
        this.resolver = new NativeMaterialResolver(materialProviders, cmm);
    }

    @Override
    public Map<String, AttributeValue> encryptItem(Map<String, AttributeValue> plaintextItem)
        throws DbesdkClientException {
        try {
            if (config.plaintextOverride() == PlaintextOverride.FORCE_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ) {
                return plaintextItem;
            }
            requireContextAttributesPresent(plaintextItem);

            Map<String, CryptoAction> actions = config.attributeActionsOnEncrypt();
            Map<String, Terminal> structured = DynamoToStruct.itemToStructured(plaintextItem, actions);
            Map<String, byte[]> baseContext =
                ItemEncryptorOperations.makeEncryptionContextForEncrypt(config, structured);
            Map<String, CryptoAction> cryptoSchema =
                ItemEncryptorOperations.configToCryptoSchema(config, structured.keySet());

            EncryptionMaterials materials =
                resolver.forEncrypt(cryptoItems(structured, cryptoSchema), baseContext, algorithmSuiteId);
            Map<String, Terminal> encrypted = StructuredEncryptionClient.encryptStructure(
                config.logicalTableName(), structured, cryptoSchema, materials).structure();

            return DynamoToStruct.structuredToItemEncrypt(encrypted, plaintextItem, actions);
        } catch (Exception failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public Map<String, AttributeValue> decryptItem(Map<String, AttributeValue> encryptedItem)
        throws DbesdkClientException {
        try {
            boolean allowsPlaintextRead =
                config.plaintextOverride() == PlaintextOverride.FORCE_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ
                    || config.plaintextOverride() == PlaintextOverride.FORBID_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ;
            if (ItemEncryptorOperations.isPlaintextItem(encryptedItem)) {
                if (allowsPlaintextRead) {
                    return encryptedItem;
                }
                throw new DynamoDbItemEncryptorException(
                    "Encrypted item missing expected header and footer attributes");
            }

            Map<String, CryptoAction> actions = config.attributeActionsOnEncrypt();
            Map<String, Terminal> structured = DynamoToStruct.itemToStructured(encryptedItem, actions);
            byte[] headerBytes = headerBytes(encryptedItem);
            Map<String, byte[]> baseContext = ItemEncryptorOperations.makeEncryptionContextForDecrypt(
                config, headerBytes[0] & 0xFF, structured);
            Map<String, AuthenticateAction> authSchema =
                ItemEncryptorOperations.configToAuthenticateSchema(config, structured.keySet());

            DecryptionMaterials materials = resolver.forDecrypt(
                config.logicalTableName(), authItems(structured, authSchema), headerBytes, baseContext);
            MapStructureOutput decrypted = StructuredEncryptionClient.decryptStructure(
                config.logicalTableName(), structured, authSchema, materials);

            return DynamoToStruct.structuredToItemDecrypt(
                decrypted.structure(), encryptedItem, decrypted.cryptoSchema());
        } catch (Exception failure) {
            throw new DbesdkClientException(failure);
        }
    }

    // Every SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT attribute must be present in the item
    // (it contributes to the bound encryption context).
    private void requireContextAttributesPresent(Map<String, AttributeValue> item) {
        config.attributeActionsOnEncrypt().forEach((name, action) -> {
            if (action == CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT && !item.containsKey(name)) {
                throw new DynamoDbItemEncryptorException("Attribute " + name
                    + " was configured with SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT"
                    + " but was not present in item to be encrypted.");
            }
        });
    }

    private static byte[] headerBytes(Map<String, AttributeValue> item) {
        AttributeValue header = item.get(HEADER_FIELD);
        if (header == null || header.b() == null) {
            throw new DynamoDbItemEncryptorException("Header field, \"aws_dbe_head\", not binary");
        }
        byte[] bytes = header.b().asByteArray();
        if (bytes.length == 0) {
            throw new DynamoDbItemEncryptorException("Unexpected empty header field.");
        }
        return bytes;
    }

    private static List<CryptoItem> cryptoItems(Map<String, Terminal> structured, Map<String, CryptoAction> schema) {
        List<CryptoItem> items = new ArrayList<>(structured.size());
        structured.forEach((name, terminal) ->
            items.add(new CryptoItem(Path.ofAttribute(name), terminal, schema.get(name))));
        return items;
    }

    private static List<AuthItem> authItems(Map<String, Terminal> structured, Map<String, AuthenticateAction> schema) {
        List<AuthItem> items = new ArrayList<>(structured.size());
        structured.forEach((name, terminal) ->
            items.add(new AuthItem(Path.ofAttribute(name), terminal, schema.get(name))));
        return items;
    }
}
