package aws.cryptography.dbesdk.testserver.server.registry;

import aws.cryptography.dbesdk.testserver.server.error.DbesdkClientException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.AuthItem;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.AuthenticateAction;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoItem;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.StructuredDataTerminal;
import software.amazon.cryptography.dbesdk.structuredencryption.StructuredEncryptionClient;
import software.amazon.cryptography.dbesdk.structuredencryption.StructuredEncryptionException;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.DecryptionMaterials;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.EncryptionMaterials;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Terminal;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.MaterialProviders;

/**
 * A {@link StructuredClient} backed by the native (non-Dafny) StructuredEncryption
 * pipeline. This class ports the outer layer of the Dafny
 * {@code Encrypt/DecryptPathStructure} operations that touches the material
 * providers; the crypto itself runs in {@link StructuredEncryptionClient}, which
 * stays MPL-free, and the CMM-to-materials resolution runs in
 * {@link NativeMaterialResolver} (shared with the item-encryptor seam). Called
 * directly, StructuredEncryption has no item base context, so it passes an empty
 * base context to the resolver.
 *
 * <p>Every failure is wrapped in {@link DbesdkClientException} so the operation
 * wrapper surfaces it as {@code DBESDKClientError} with the message unmodified.
 */
public final class NativeStructuredClient implements StructuredClient {

    private static final String HEADER_FIELD = "aws_dbe_head";

    private final NativeMaterialResolver resolver;

    public NativeStructuredClient(MaterialProviders materialProviders, ICryptographicMaterialsManager cmm) {
        this.resolver = new NativeMaterialResolver(materialProviders, cmm);
    }

    @Override
    public Map<String, StructuredDataTerminal> encryptStructure(
            String tableName,
            Map<String, StructuredDataTerminal> plaintextStructure,
            Map<String, CryptoAction> cryptoSchema)
        throws DbesdkClientException {
        try {
            EncryptionMaterials materials = resolver.forEncrypt(
                StructuredTypeAdapters.toNativeItemsForMaterials(plaintextStructure, cryptoSchema),
                Map.of(), null);
            Map<String, Terminal> encrypted = StructuredEncryptionClient.encryptStructure(
                tableName,
                StructuredTypeAdapters.toNativeTerminalMap(plaintextStructure),
                StructuredTypeAdapters.toNativeSchema(cryptoSchema),
                materials).structure();
            return StructuredTypeAdapters.toPublishedTerminalMap(encrypted);
        } catch (Exception failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public Map<String, StructuredDataTerminal> decryptStructure(
            String tableName,
            Map<String, StructuredDataTerminal> encryptedStructure,
            Map<String, AuthenticateAction> authenticateSchema)
        throws DbesdkClientException {
        try {
            var authItems = StructuredTypeAdapters.toNativeAuthItems(toAuthItems(encryptedStructure, authenticateSchema));
            byte[] headerBytes = StructuredTypeAdapters.toNativeTerminal(
                requireHeaderField(encryptedStructure)).value();
            DecryptionMaterials materials = resolver.forDecrypt(tableName, authItems, headerBytes, Map.of());
            Map<String, Terminal> decrypted = StructuredEncryptionClient.decryptStructure(
                tableName,
                StructuredTypeAdapters.toNativeTerminalMap(encryptedStructure),
                StructuredTypeAdapters.toNativeAuthSchema(authenticateSchema),
                materials).structure();
            return StructuredTypeAdapters.toPublishedTerminalMap(decrypted);
        } catch (Exception failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public List<CryptoItem> encryptPathStructure(String tableName, List<CryptoItem> plaintextStructure)
        throws DbesdkClientException {
        try {
            var items = StructuredTypeAdapters.toNativeItems(plaintextStructure);
            EncryptionMaterials materials = resolver.forEncrypt(items, Map.of(), null);
            var encrypted = StructuredEncryptionClient.encryptPathStructure(tableName, items, materials).structure();
            return StructuredTypeAdapters.toPublishedItems(encrypted);
        } catch (Exception failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public List<CryptoItem> decryptPathStructure(String tableName, List<AuthItem> encryptedStructure)
        throws DbesdkClientException {
        try {
            var authItems = StructuredTypeAdapters.toNativeAuthItems(encryptedStructure);
            byte[] headerBytes = headerBytesFromAuth(authItems);
            DecryptionMaterials materials = resolver.forDecrypt(tableName, authItems, headerBytes, Map.of());
            var decrypted = StructuredEncryptionClient.decryptPathStructure(tableName, authItems, materials).structure();
            return StructuredTypeAdapters.toPublishedItems(decrypted);
        } catch (Exception failure) {
            throw new DbesdkClientException(failure);
        }
    }

    /** Resolve each Auth List item's Crypto Action from a serialized header. No CMM, no crypto. */
    public static List<CryptoItem> resolveAuthActions(
            String tableName, List<AuthItem> authActions, byte[] headerBytes)
        throws DbesdkClientException {
        try {
            var resolved = StructuredEncryptionClient.resolveAuthActions(
                tableName, StructuredTypeAdapters.toNativeAuthItems(authActions), headerBytes);
            return StructuredTypeAdapters.toPublishedItems(resolved);
        } catch (Exception failure) {
            throw new DbesdkClientException(failure);
        }
    }

    private static List<AuthItem> toAuthItems(
            Map<String, StructuredDataTerminal> encryptedStructure,
            Map<String, AuthenticateAction> authenticateSchema) {
        List<AuthItem> items = new ArrayList<>();
        encryptedStructure.forEach((key, terminal) -> {
            AuthenticateAction action = authenticateSchema.get(key);
            if (action != null) {
                items.add(AuthItem.builder()
                    .key(StructuredTypeAdapters.toPublishedPath(
                        software.amazon.cryptography.dbesdk.structuredencryption.internal.Path.ofAttribute(key)))
                    .data(terminal)
                    .action(action)
                    .build());
            }
        });
        return items;
    }

    private static byte[] headerBytesFromAuth(
            List<software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthItem> authItems) {
        for (var item : authItems) {
            if (item.key().segments().equals(List.of(HEADER_FIELD))) {
                return item.data().value();
            }
        }
        throw new StructuredEncryptionException("Structured data is missing the required header field.");
    }

    private static StructuredDataTerminal requireHeaderField(Map<String, StructuredDataTerminal> encryptedStructure) {
        StructuredDataTerminal header = encryptedStructure.get(HEADER_FIELD);
        if (header == null) {
            throw new StructuredEncryptionException("Structured data is missing the required header field.");
        }
        return header;
    }
}
