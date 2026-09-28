package aws.cryptography.dbesdk.testserver.server.registry;

import aws.cryptography.dbesdk.testserver.server.error.DbesdkClientException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.AuthItem;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.AuthenticateAction;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoItem;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.StructuredDataTerminal;
import software.amazon.cryptography.dbesdk.structuredencryption.StructuredEncryptionClient;
import software.amazon.cryptography.dbesdk.structuredencryption.StructuredEncryptionException;
import software.amazon.cryptography.dbesdk.structuredencryption.V2EncryptionContext;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.AlgorithmSuite;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.DecryptionMaterials;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.EncryptedDataKey;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.EncryptionMaterials;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Terminal;
import software.amazon.cryptography.dbesdk.structuredencryption.wire.Header;
import software.amazon.cryptography.dbesdk.structuredencryption.wire.PartialHeader;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteInfo;
import software.amazon.cryptography.materialproviders.model.CommitmentPolicy;
import software.amazon.cryptography.materialproviders.model.CreateRequiredEncryptionContextCMMInput;
import software.amazon.cryptography.materialproviders.model.DBEAlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.DBECommitmentPolicy;
import software.amazon.cryptography.materialproviders.model.DecryptMaterialsInput;
import software.amazon.cryptography.materialproviders.model.GetEncryptionMaterialsInput;

/**
 * A {@link StructuredClient} backed by the native (non-Dafny) StructuredEncryption
 * pipeline. This class ports the outer layer of the Dafny
 * {@code Encrypt/DecryptPathStructure} operations — the parts the native pipeline
 * deliberately leaves out because they touch the material providers: resolving
 * materials from the configured CMM, and, for a record with a
 * SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT field, building the version-2 encryption
 * context and wrapping the CMM in a Required-Encryption-Context CMM. The crypto
 * itself runs in {@link StructuredEncryptionClient}, which stays MPL-free.
 *
 * <p>Every failure is wrapped in {@link DbesdkClientException} so the operation
 * wrapper surfaces it as {@code DBESDKClientError} with the message unmodified.
 */
public final class NativeStructuredClient implements StructuredClient {

    private static final CommitmentPolicy DBE_POLICY = CommitmentPolicy.builder()
        .DBE(DBECommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
        .build();
    private static final String HEADER_FIELD = "aws_dbe_head";

    private final MaterialProviders materialProviders;
    private final ICryptographicMaterialsManager cmm;

    public NativeStructuredClient(MaterialProviders materialProviders, ICryptographicMaterialsManager cmm) {
        this.materialProviders = materialProviders;
        this.cmm = cmm;
    }

    @Override
    public Map<String, StructuredDataTerminal> encryptStructure(
            String tableName,
            Map<String, StructuredDataTerminal> plaintextStructure,
            Map<String, CryptoAction> cryptoSchema)
        throws DbesdkClientException {
        try {
            EncryptionMaterials materials = resolveEncryptionMaterials(
                StructuredTypeAdapters.toNativeItemsForMaterials(plaintextStructure, cryptoSchema));
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
            DecryptionMaterials materials = resolveDecryptionMaterials(tableName, authItems, headerBytes);
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
            EncryptionMaterials materials = resolveEncryptionMaterials(items);
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
            DecryptionMaterials materials = resolveDecryptionMaterials(tableName, authItems, headerBytes);
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

    private EncryptionMaterials resolveEncryptionMaterials(
            List<software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoItem> items) {
        int encryptedTerminalCount = 0;
        long encryptedValuesSize = 0;
        for (var item : items) {
            if (item.action()
                    == software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction.ENCRYPT_AND_SIGN) {
                encryptedTerminalCount++;
                encryptedValuesSize += item.data().value().length;
            }
        }

        Map<String, byte[]> v2Context = V2EncryptionContext.build(items);
        ICryptographicMaterialsManager effectiveCmm = v2Context.isEmpty() ? cmm : requiredEcCmm(v2Context.keySet());
        long maxPlaintextLength = 2L * encryptedTerminalCount + encryptedValuesSize;

        software.amazon.cryptography.materialproviders.model.EncryptionMaterials mpl =
            effectiveCmm.GetEncryptionMaterials(GetEncryptionMaterialsInput.builder()
                .encryptionContext(toStringContext(v2Context))
                .commitmentPolicy(DBE_POLICY)
                .maxPlaintextLength(maxPlaintextLength)
                .build()).encryptionMaterials();

        AlgorithmSuite suite = nativeSuite(mpl.algorithmSuite());
        List<EncryptedDataKey> edks = new ArrayList<>(mpl.encryptedDataKeys().size());
        for (var edk : mpl.encryptedDataKeys()) {
            edks.add(new EncryptedDataKey(
                edk.keyProviderId().getBytes(StandardCharsets.UTF_8),
                bytes(edk.keyProviderInfo()),
                bytes(edk.ciphertext())));
        }
        List<byte[]> symmetricSigningKeys = new ArrayList<>(mpl.symmetricSigningKeys().size());
        for (ByteBuffer key : mpl.symmetricSigningKeys()) {
            symmetricSigningKeys.add(bytes(key));
        }
        PrivateKey signingKey = suite.hasEcdsaSignature()
            ? MplEcKeyDecoder.decodePrivateKey(bytes(mpl.signingKey()))
            : null;

        return new EncryptionMaterials(
            bytes(mpl.plaintextDataKey()), suite, edks,
            toByteContext(mpl.encryptionContext()), Set.copyOf(mpl.requiredEncryptionContextKeys()),
            symmetricSigningKeys, signingKey);
    }

    private DecryptionMaterials resolveDecryptionMaterials(
            String tableName,
            List<software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthItem> authItems,
            byte[] headerBytes) {
        PartialHeader header = Header.deserialize(headerBytes);

        // Rebuild the version-2 context from the record's plaintext SIGN_AND_INCLUDE
        // fields; empty for a version-1 record, which then uses the base CMM.
        var resolved = StructuredEncryptionClient.resolveAuthActions(tableName, authItems, headerBytes);
        Map<String, byte[]> v2Context = V2EncryptionContext.build(resolved);
        ICryptographicMaterialsManager effectiveCmm = v2Context.isEmpty() ? cmm : requiredEcCmm(v2Context.keySet());

        List<software.amazon.cryptography.materialproviders.model.EncryptedDataKey> edks =
            new ArrayList<>(header.dataKeys().size());
        for (EncryptedDataKey edk : header.dataKeys()) {
            edks.add(software.amazon.cryptography.materialproviders.model.EncryptedDataKey.builder()
                .keyProviderId(new String(edk.keyProviderId(), StandardCharsets.UTF_8))
                .keyProviderInfo(ByteBuffer.wrap(edk.keyProviderInfo()))
                .ciphertext(ByteBuffer.wrap(edk.ciphertext()))
                .build());
        }

        software.amazon.cryptography.materialproviders.model.DecryptionMaterials mpl =
            effectiveCmm.DecryptMaterials(DecryptMaterialsInput.builder()
                .algorithmSuiteId(AlgorithmSuiteId.builder().DBE(suiteIdForFlavor(header.flavor())).build())
                .commitmentPolicy(DBE_POLICY)
                .encryptedDataKeys(edks)
                .encryptionContext(toStringContext(header.encryptionContext()))
                .reproducedEncryptionContext(toStringContext(v2Context))
                .build()).decryptionMaterials();

        AlgorithmSuite suite = nativeSuite(mpl.algorithmSuite());
        PublicKey verificationKey = suite.hasEcdsaSignature()
            ? MplEcKeyDecoder.decodePublicKey(bytes(mpl.verificationKey()))
            : null;

        return new DecryptionMaterials(
            bytes(mpl.plaintextDataKey()), suite,
            toByteContext(mpl.encryptionContext()), bytes(mpl.symmetricSigningKey()), verificationKey);
    }

    private ICryptographicMaterialsManager requiredEcCmm(Set<String> requiredKeys) {
        return materialProviders.CreateRequiredEncryptionContextCMM(
            CreateRequiredEncryptionContextCMMInput.builder()
                .underlyingCMM(cmm)
                .requiredEncryptionContextKeys(new ArrayList<>(requiredKeys))
                .build());
    }

    // Both defined DBE suites use SHA-512 key derivation, SHA-512 commitment,
    // SHA-384 symmetric signature, and 256-bit keys (AlgorithmSuites.dfy); only the
    // format flavor and ECDSA presence distinguish them, so read those from the
    // resolved suite and take the rest as the shared DBE constants.
    private static AlgorithmSuite nativeSuite(AlgorithmSuiteInfo info) {
        byte flavor = bytes(info.binaryId())[1];
        boolean hasEcdsa = info.signature() != null && info.signature().ECDSA() != null;
        return new AlgorithmSuite(flavor, hasEcdsa, "HmacSHA512", "HmacSHA512", "HmacSHA384", 32, 32);
    }

    private static DBEAlgorithmSuiteId suiteIdForFlavor(byte flavor) {
        return switch (flavor) {
            case 0x00 -> DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384;
            case 0x01 -> DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384;
            default -> throw new StructuredEncryptionException(
                "Unknown message format flavor: " + (flavor & 0xFF));
        };
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

    private static Map<String, String> toStringContext(Map<String, byte[]> context) {
        Map<String, String> out = new LinkedHashMap<>();
        context.forEach((key, value) -> out.put(key, new String(value, StandardCharsets.UTF_8)));
        return out;
    }

    private static Map<String, byte[]> toByteContext(Map<String, String> context) {
        Map<String, byte[]> out = new LinkedHashMap<>();
        context.forEach((key, value) -> out.put(key, value.getBytes(StandardCharsets.UTF_8)));
        return out;
    }

    private static byte[] bytes(ByteBuffer buffer) {
        ByteBuffer duplicate = buffer.duplicate();
        byte[] out = new byte[duplicate.remaining()];
        duplicate.get(out);
        return out;
    }
}
