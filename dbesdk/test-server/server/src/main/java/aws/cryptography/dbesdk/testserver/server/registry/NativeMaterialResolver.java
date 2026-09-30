package aws.cryptography.dbesdk.testserver.server.registry;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import software.amazon.cryptography.dbesdk.structuredencryption.StructuredEncryptionClient;
import software.amazon.cryptography.dbesdk.structuredencryption.StructuredEncryptionException;
import software.amazon.cryptography.dbesdk.structuredencryption.V2EncryptionContext;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.AlgorithmSuite;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthItem;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoItem;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.DecryptionMaterials;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.EncryptedDataKey;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.EncryptionMaterials;
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
 * Resolves StructuredEncryption {@link EncryptionMaterials}/{@link DecryptionMaterials}
 * from a Material Providers CMM — the MPL-facing step the MPL-free crypto core
 * deliberately leaves out. Shared by the StructuredEncryption seam
 * ({@link NativeStructuredClient}) and the DynamoDbItemEncryptor seam
 * ({@code NativeItemEncryptorClient}).
 *
 * <p>The only difference between the two callers is the {@code baseContext}: the
 * StructuredEncryption seam passes an empty map (its whole context is the
 * version-2 SIGN_AND_INCLUDE contribution), while the item encryptor passes its
 * DynamoDB item base context (table/key names, plus encoded key values for
 * version 1). Either way, the base context is merged with the record's
 * version-2 contribution and every key of the union is marked required — so a
 * Required-Encryption-Context CMM keeps them out of the stored header but binds
 * them in the signature, and the same union is reproduced on decrypt.
 */
final class NativeMaterialResolver {

    private static final CommitmentPolicy DBE_POLICY = CommitmentPolicy.builder()
        .DBE(DBECommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
        .build();

    private final MaterialProviders materialProviders;
    private final ICryptographicMaterialsManager cmm;

    NativeMaterialResolver(MaterialProviders materialProviders, ICryptographicMaterialsManager cmm) {
        this.materialProviders = materialProviders;
        this.cmm = cmm;
    }

    EncryptionMaterials forEncrypt(
            List<CryptoItem> items, Map<String, byte[]> baseContext, DBEAlgorithmSuiteId algorithmSuiteId) {
        int encryptedTerminalCount = 0;
        long encryptedValuesSize = 0;
        for (CryptoItem item : items) {
            if (item.action() == software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction.ENCRYPT_AND_SIGN) {
                encryptedTerminalCount++;
                encryptedValuesSize += item.data().value().length;
            }
        }

        Map<String, byte[]> context = merge(baseContext, V2EncryptionContext.build(items));
        ICryptographicMaterialsManager effectiveCmm = context.isEmpty() ? cmm : requiredEcCmm(context.keySet());
        long maxPlaintextLength = 2L * encryptedTerminalCount + encryptedValuesSize;

        GetEncryptionMaterialsInput.Builder request = GetEncryptionMaterialsInput.builder()
            .encryptionContext(toStringContext(context))
            .commitmentPolicy(DBE_POLICY)
            .maxPlaintextLength(maxPlaintextLength);
        if (algorithmSuiteId != null) {
            request.algorithmSuiteId(AlgorithmSuiteId.builder().DBE(algorithmSuiteId).build());
        }

        software.amazon.cryptography.materialproviders.model.EncryptionMaterials mpl =
            effectiveCmm.GetEncryptionMaterials(request.build()).encryptionMaterials();

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

    DecryptionMaterials forDecrypt(
            String tableName, List<AuthItem> authItems, byte[] headerBytes, Map<String, byte[]> baseContext) {
        PartialHeader header = Header.deserialize(headerBytes);

        // Rebuild the version-2 contribution from the record's plaintext SIGN_AND_INCLUDE
        // fields and union it with the caller's base context; this is the encryption
        // context that was bound at encrypt time and must be reproduced to verify.
        List<CryptoItem> resolved = StructuredEncryptionClient.resolveAuthActions(tableName, authItems, headerBytes);
        Map<String, byte[]> reproduced = merge(baseContext, V2EncryptionContext.build(resolved));
        ICryptographicMaterialsManager effectiveCmm = reproduced.isEmpty() ? cmm : requiredEcCmm(reproduced.keySet());

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
                .reproducedEncryptionContext(toStringContext(reproduced))
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

    // base first, then the version-2 contribution; the two never share a key (the
    // base carries table/key names and version-1 key values, the version-2 map
    // carries aws-crypto-attr.<field> and the legend).
    private static Map<String, byte[]> merge(Map<String, byte[]> baseContext, Map<String, byte[]> v2Context) {
        Map<String, byte[]> merged = new LinkedHashMap<>(baseContext);
        merged.putAll(v2Context);
        return merged;
    }

    // Both defined DBE suites use SHA-512 key derivation, SHA-512 commitment,
    // SHA-384 symmetric signature, and 256-bit keys (AlgorithmSuites.dfy); only the
    // format flavor and ECDSA presence distinguish them.
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
