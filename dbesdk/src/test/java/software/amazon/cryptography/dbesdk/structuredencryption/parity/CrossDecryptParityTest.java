package software.amazon.cryptography.dbesdk.structuredencryption.parity;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.StructuredEncryption;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.DecryptStructureInput;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.EncryptStructureInput;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.StructuredDataTerminal;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.StructuredEncryptionConfig;
import software.amazon.cryptography.dbesdk.structuredencryption.StructuredEncryptionClient;
import software.amazon.cryptography.dbesdk.structuredencryption.V2EncryptionContext;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.AlgorithmSuite;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthenticateAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoItem;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.DecryptionMaterials;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.EncryptionMaterials;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Path;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Terminal;
import software.amazon.cryptography.dbesdk.structuredencryption.wire.Header;
import software.amazon.cryptography.dbesdk.structuredencryption.wire.PartialHeader;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.CommitmentPolicy;
import software.amazon.cryptography.materialproviders.model.CreateDefaultCryptographicMaterialsManagerInput;
import software.amazon.cryptography.materialproviders.model.CreateRawAesKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRequiredEncryptionContextCMMInput;
import software.amazon.cryptography.materialproviders.model.DBEAlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.DBECommitmentPolicy;
import software.amazon.cryptography.materialproviders.model.DecryptMaterialsInput;
import software.amazon.cryptography.materialproviders.model.GetEncryptionMaterialsInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;

/**
 * Proves byte-level interop between the native pipeline and the published Dafny
 * DB-ESDK: a record encrypted by one MUST decrypt under the other, in both
 * directions, for both the non-signing suite (recipient tags only) and the
 * ECDSA P-384 signing suite. A Raw AES keyring keeps it offline.
 *
 * <p>Materials are resolved once via the MPL CMM and fed to both sides so they
 * share the same data key, signing keys, and encryption context. The signing
 * suite's asymmetric keys arrive MPL-encoded (a signed big-endian private
 * scalar; a SEC-1 compressed public point), which this test decodes to JCE keys
 * the native footer signs/verifies with — the same encoding the MPL uses.
 */
class CrossDecryptParityTest {

    private static final String TABLE = "table";
    private static final byte[] TYPE_ID = {0, 1};

    private static final AlgorithmSuite NON_SIGNING =
        new AlgorithmSuite((byte) 0x00, false, "HmacSHA512", "HmacSHA512", "HmacSHA384", 32, 32);
    private static final AlgorithmSuite SIGNING =
        new AlgorithmSuite((byte) 0x01, true, "HmacSHA512", "HmacSHA512", "HmacSHA384", 32, 32);

    private static final CommitmentPolicy DBE_POLICY = CommitmentPolicy.builder()
        .DBE(DBECommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT).build();
    private static final DBEAlgorithmSuiteId NON_SIGNING_DBE_ID =
        DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384;
    private static final DBEAlgorithmSuiteId SIGNING_DBE_ID =
        DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384;

    private MaterialProviders materialProviders;
    private ICryptographicMaterialsManager cmm;
    private StructuredEncryption dafny;

    @BeforeEach
    void setUp() {
        materialProviders = MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build()).build();
        byte[] wrappingKey = new byte[32];
        Arrays.fill(wrappingKey, (byte) 0x2a);
        cmm = materialProviders.CreateDefaultCryptographicMaterialsManager(
            CreateDefaultCryptographicMaterialsManagerInput.builder()
                .keyring(materialProviders.CreateRawAesKeyring(CreateRawAesKeyringInput.builder()
                    .keyNamespace("ns").keyName("key")
                    .wrappingKey(ByteBuffer.wrap(wrappingKey))
                    .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
                    .build()))
                .build());
        dafny = StructuredEncryption.builder()
            .StructuredEncryptionConfig(StructuredEncryptionConfig.builder().build()).build();
    }

    @Test
    void nonSigningNativeEncryptDecryptsUnderDafny() {
        assertNativeEncryptDafnyDecrypt(NON_SIGNING, NON_SIGNING_DBE_ID);
    }

    @Test
    void signingNativeEncryptDecryptsUnderDafny() {
        assertNativeEncryptDafnyDecrypt(SIGNING, SIGNING_DBE_ID);
    }

    @Test
    void nonSigningDafnyEncryptDecryptsUnderNative() {
        assertDafnyEncryptNativeDecrypt(NON_SIGNING, NON_SIGNING_DBE_ID);
    }

    @Test
    void signingDafnyEncryptDecryptsUnderNative() {
        assertDafnyEncryptNativeDecrypt(SIGNING, SIGNING_DBE_ID);
    }

    // A SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT field forces version 2: its value is
    // added to the encryption context (kept out of the stored header by a Required
    // Encryption Context CMM, but bound in the footer signature). The native side
    // builds that context with V2EncryptionContext and resolves materials through
    // the MPL Required-EC CMM, exactly as the Dafny operation does internally.
    @Test
    void v2NativeEncryptDecryptsUnderDafny() {
        List<CryptoItem> items = List.of(
            new CryptoItem(Path.ofAttribute("a"), nativeTerminal("alpha"), CryptoAction.ENCRYPT_AND_SIGN),
            new CryptoItem(Path.ofAttribute("b"), nativeTerminal("bravo"), CryptoAction.SIGN_ONLY),
            new CryptoItem(Path.ofAttribute("c"), nativeTerminal("charlie"), CryptoAction.DO_NOTHING),
            new CryptoItem(Path.ofAttribute("d"), nativeTerminal("delta"),
                CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT));

        Map<String, byte[]> v2Context = V2EncryptionContext.build(items);
        ICryptographicMaterialsManager requiredEcCmm = requiredEcCmm(new ArrayList<>(v2Context.keySet()));
        software.amazon.cryptography.materialproviders.model.EncryptionMaterials mpl =
            requiredEcCmm.GetEncryptionMaterials(GetEncryptionMaterialsInput.builder()
                .encryptionContext(toStringMap(v2Context))
                .commitmentPolicy(DBE_POLICY)
                .algorithmSuiteId(AlgorithmSuiteId.builder().DBE(NON_SIGNING_DBE_ID).build())
                .maxPlaintextLength(1000L)
                .build()).encryptionMaterials();

        List<CryptoItem> encrypted = StructuredEncryptionClient.encryptPathStructure(
            TABLE, items, nativeEncryptionMaterials(mpl, NON_SIGNING)).structure();

        Map<String, StructuredDataTerminal> encryptedStructure = new LinkedHashMap<>();
        for (CryptoItem item : encrypted) {
            encryptedStructure.put(item.key().segments().get(0), StructuredDataTerminal.builder()
                .value(ByteBuffer.wrap(item.data().value()))
                .typeId(ByteBuffer.wrap(item.data().typeId()))
                .build());
        }

        Map<String, StructuredDataTerminal> dafnyDecrypted = dafny.DecryptStructure(
            DecryptStructureInput.builder()
                .tableName(TABLE)
                .encryptedStructure(encryptedStructure)
                .authenticateSchema(publishedAuthenticateSchema(encryptedStructure.keySet()))
                .cmm(cmm)
                .build()).plaintextStructure();

        assertEquals(Set.of("a", "b", "c", "d"), dafnyDecrypted.keySet());
        assertArrayEquals("alpha".getBytes(StandardCharsets.UTF_8), toBytes(dafnyDecrypted.get("a").value()));
        assertArrayEquals("bravo".getBytes(StandardCharsets.UTF_8), toBytes(dafnyDecrypted.get("b").value()));
        assertArrayEquals("charlie".getBytes(StandardCharsets.UTF_8), toBytes(dafnyDecrypted.get("c").value()));
        assertArrayEquals("delta".getBytes(StandardCharsets.UTF_8), toBytes(dafnyDecrypted.get("d").value()));
    }

    @Test
    void v2DafnyEncryptDecryptsUnderNative() {
        Map<String, StructuredDataTerminal> plaintext = new LinkedHashMap<>();
        plaintext.put("a", publishedTerminal("alpha"));
        plaintext.put("b", publishedTerminal("bravo"));
        plaintext.put("c", publishedTerminal("charlie"));
        plaintext.put("d", publishedTerminal("delta"));
        Map<String, software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction> schema =
            new LinkedHashMap<>();
        schema.put("a", software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction.ENCRYPT_AND_SIGN);
        schema.put("b", software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction.SIGN_ONLY);
        schema.put("c", software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction.DO_NOTHING);
        schema.put("d", software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);

        Map<String, StructuredDataTerminal> dafnyEncrypted = dafny.EncryptStructure(
            EncryptStructureInput.builder()
                .tableName(TABLE)
                .plaintextStructure(plaintext)
                .cryptoSchema(schema)
                .algorithmSuiteId(NON_SIGNING_DBE_ID)
                .cmm(cmm)
                .build()).encryptedStructure();

        Map<String, Terminal> nativeEncrypted = toNativeTerminals(dafnyEncrypted);
        // A SIGN_AND_INCLUDE field is signed but stored in plaintext, so its value
        // is read straight from the record to rebuild the same context Dafny bound.
        Map<String, byte[]> v2Context = V2EncryptionContext.build(List.of(new CryptoItem(
            Path.ofAttribute("d"), nativeEncrypted.get("d"),
            CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT)));

        DecryptionMaterials materials =
            nativeV2DecryptionMaterials(nativeEncrypted.get("aws_dbe_head").value(), v2Context);
        Map<String, Terminal> nativeDecrypted = StructuredEncryptionClient.decryptStructure(
            TABLE, nativeEncrypted, nativeAuthenticateSchema(nativeEncrypted.keySet()), materials).structure();

        assertEquals(Set.of("a", "b", "c", "d"), nativeDecrypted.keySet());
        assertArrayEquals("alpha".getBytes(StandardCharsets.UTF_8), nativeDecrypted.get("a").value());
        assertArrayEquals("bravo".getBytes(StandardCharsets.UTF_8), nativeDecrypted.get("b").value());
        assertArrayEquals("charlie".getBytes(StandardCharsets.UTF_8), nativeDecrypted.get("c").value());
        assertArrayEquals("delta".getBytes(StandardCharsets.UTF_8), nativeDecrypted.get("d").value());
    }

    private void assertNativeEncryptDafnyDecrypt(AlgorithmSuite suite, DBEAlgorithmSuiteId dbeId) {
        software.amazon.cryptography.materialproviders.model.EncryptionMaterials mpl =
            cmm.GetEncryptionMaterials(GetEncryptionMaterialsInput.builder()
                .encryptionContext(Map.of())
                .commitmentPolicy(DBE_POLICY)
                .algorithmSuiteId(AlgorithmSuiteId.builder().DBE(dbeId).build())
                .maxPlaintextLength(1000L)
                .build()).encryptionMaterials();

        Map<String, Terminal> nativeEncrypted = StructuredEncryptionClient.encryptStructure(
            TABLE, nativePlaintextMap(), nativeCryptoSchema(), nativeEncryptionMaterials(mpl, suite)).structure();

        Map<String, StructuredDataTerminal> dafnyDecrypted = dafny.DecryptStructure(
            DecryptStructureInput.builder()
                .tableName(TABLE)
                .encryptedStructure(toPublishedTerminals(nativeEncrypted))
                .authenticateSchema(publishedAuthenticateSchema(nativeEncrypted.keySet()))
                .cmm(cmm)
                .build()).plaintextStructure();

        assertEquals(Set.of("a", "b", "c"), dafnyDecrypted.keySet());
        assertArrayEquals("alpha".getBytes(StandardCharsets.UTF_8), toBytes(dafnyDecrypted.get("a").value()));
        assertArrayEquals("bravo".getBytes(StandardCharsets.UTF_8), toBytes(dafnyDecrypted.get("b").value()));
        assertArrayEquals("charlie".getBytes(StandardCharsets.UTF_8), toBytes(dafnyDecrypted.get("c").value()));
    }

    private void assertDafnyEncryptNativeDecrypt(AlgorithmSuite suite, DBEAlgorithmSuiteId dbeId) {
        Map<String, StructuredDataTerminal> dafnyEncrypted = dafny.EncryptStructure(
            EncryptStructureInput.builder()
                .tableName(TABLE)
                .plaintextStructure(publishedPlaintext())
                .cryptoSchema(publishedCryptoSchema())
                .algorithmSuiteId(dbeId)
                .cmm(cmm)
                .build()).encryptedStructure();

        Map<String, Terminal> nativeEncrypted = toNativeTerminals(dafnyEncrypted);
        Map<String, Terminal> nativeDecrypted = StructuredEncryptionClient.decryptStructure(
            TABLE, nativeEncrypted,
            nativeAuthenticateSchema(nativeEncrypted.keySet()),
            nativeDecryptionMaterials(nativeEncrypted.get("aws_dbe_head").value(), suite, dbeId)).structure();

        assertEquals(Set.of("a", "b", "c"), nativeDecrypted.keySet());
        assertArrayEquals("alpha".getBytes(StandardCharsets.UTF_8), nativeDecrypted.get("a").value());
        assertArrayEquals("bravo".getBytes(StandardCharsets.UTF_8), nativeDecrypted.get("b").value());
        assertArrayEquals("charlie".getBytes(StandardCharsets.UTF_8), nativeDecrypted.get("c").value());
    }

    private static EncryptionMaterials nativeEncryptionMaterials(
            software.amazon.cryptography.materialproviders.model.EncryptionMaterials mpl,
            AlgorithmSuite suite) {
        List<software.amazon.cryptography.dbesdk.structuredencryption.internal.EncryptedDataKey> edks =
            mpl.encryptedDataKeys().stream()
                .map(edk -> new software.amazon.cryptography.dbesdk.structuredencryption.internal.EncryptedDataKey(
                    edk.keyProviderId().getBytes(StandardCharsets.UTF_8),
                    toBytes(edk.keyProviderInfo()),
                    toBytes(edk.ciphertext())))
                .toList();
        List<byte[]> signingKeys = mpl.symmetricSigningKeys().stream().map(CrossDecryptParityTest::toBytes).toList();
        PrivateKey signingKey = suite.hasEcdsaSignature() ? decodePrivateKey(toBytes(mpl.signingKey())) : null;

        return new EncryptionMaterials(
            toBytes(mpl.plaintextDataKey()), suite, edks,
            toByteMap(mpl.encryptionContext()), Set.copyOf(mpl.requiredEncryptionContextKeys()),
            signingKeys, signingKey);
    }

    private DecryptionMaterials nativeDecryptionMaterials(
            byte[] headerBytes, AlgorithmSuite suite, DBEAlgorithmSuiteId dbeId) {
        PartialHeader header = Header.deserialize(headerBytes);

        software.amazon.cryptography.materialproviders.model.DecryptionMaterials mpl =
            cmm.DecryptMaterials(DecryptMaterialsInput.builder()
                .algorithmSuiteId(AlgorithmSuiteId.builder().DBE(dbeId).build())
                .commitmentPolicy(DBE_POLICY)
                .encryptedDataKeys(toMplEdks(header))
                .encryptionContext(toStringMap(header.encryptionContext()))
                .reproducedEncryptionContext(Map.of())
                .build()).decryptionMaterials();

        PublicKey verificationKey = suite.hasEcdsaSignature() ? decodePublicKey(toBytes(mpl.verificationKey())) : null;
        return new DecryptionMaterials(
            toBytes(mpl.plaintextDataKey()), suite,
            toByteMap(mpl.encryptionContext()), toBytes(mpl.symmetricSigningKey()), verificationKey);
    }

    // Version-2 decrypt: the SIGN_AND_INCLUDE entries were kept out of the stored
    // header, so they are supplied as reproduced context to the Required-EC CMM,
    // which restores the full context used as the footer AAD and unwrap AAD.
    private DecryptionMaterials nativeV2DecryptionMaterials(byte[] headerBytes, Map<String, byte[]> v2Context) {
        PartialHeader header = Header.deserialize(headerBytes);

        software.amazon.cryptography.materialproviders.model.DecryptionMaterials mpl =
            requiredEcCmm(new ArrayList<>(v2Context.keySet())).DecryptMaterials(DecryptMaterialsInput.builder()
                .algorithmSuiteId(AlgorithmSuiteId.builder().DBE(NON_SIGNING_DBE_ID).build())
                .commitmentPolicy(DBE_POLICY)
                .encryptedDataKeys(toMplEdks(header))
                .encryptionContext(toStringMap(header.encryptionContext()))
                .reproducedEncryptionContext(toStringMap(v2Context))
                .build()).decryptionMaterials();

        return new DecryptionMaterials(
            toBytes(mpl.plaintextDataKey()), NON_SIGNING,
            toByteMap(mpl.encryptionContext()), toBytes(mpl.symmetricSigningKey()), null);
    }

    private ICryptographicMaterialsManager requiredEcCmm(List<String> requiredKeys) {
        return materialProviders.CreateRequiredEncryptionContextCMM(
            CreateRequiredEncryptionContextCMMInput.builder()
                .underlyingCMM(cmm)
                .requiredEncryptionContextKeys(requiredKeys)
                .build());
    }

    private static List<software.amazon.cryptography.materialproviders.model.EncryptedDataKey> toMplEdks(
            PartialHeader header) {
        return header.dataKeys().stream()
            .map(edk -> software.amazon.cryptography.materialproviders.model.EncryptedDataKey.builder()
                .keyProviderId(new String(edk.keyProviderId(), StandardCharsets.UTF_8))
                .keyProviderInfo(ByteBuffer.wrap(edk.keyProviderInfo()))
                .ciphertext(ByteBuffer.wrap(edk.ciphertext()))
                .build())
            .toList();
    }

    private static Map<String, Terminal> nativePlaintextMap() {
        Map<String, Terminal> map = new LinkedHashMap<>();
        map.put("a", nativeTerminal("alpha"));
        map.put("b", nativeTerminal("bravo"));
        map.put("c", nativeTerminal("charlie"));
        return map;
    }

    private static Map<String, CryptoAction> nativeCryptoSchema() {
        Map<String, CryptoAction> schema = new LinkedHashMap<>();
        schema.put("a", CryptoAction.ENCRYPT_AND_SIGN);
        schema.put("b", CryptoAction.SIGN_ONLY);
        schema.put("c", CryptoAction.DO_NOTHING);
        return schema;
    }

    private static Map<String, AuthenticateAction> nativeAuthenticateSchema(Set<String> keys) {
        Map<String, AuthenticateAction> schema = new LinkedHashMap<>();
        for (String key : keys) {
            schema.put(key, isSigned(key) ? AuthenticateAction.SIGN : AuthenticateAction.DO_NOT_SIGN);
        }
        return schema;
    }

    private static Map<String, StructuredDataTerminal> publishedPlaintext() {
        Map<String, StructuredDataTerminal> map = new LinkedHashMap<>();
        map.put("a", publishedTerminal("alpha"));
        map.put("b", publishedTerminal("bravo"));
        map.put("c", publishedTerminal("charlie"));
        return map;
    }

    private static Map<String, software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction>
            publishedCryptoSchema() {
        Map<String, software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction> schema =
            new LinkedHashMap<>();
        schema.put("a", software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction.ENCRYPT_AND_SIGN);
        schema.put("b", software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction.SIGN_ONLY);
        schema.put("c", software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction.DO_NOTHING);
        return schema;
    }

    private static Map<String, software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.AuthenticateAction>
            publishedAuthenticateSchema(Set<String> keys) {
        Map<String, software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.AuthenticateAction> schema =
            new LinkedHashMap<>();
        for (String key : keys) {
            schema.put(key, isSigned(key)
                ? software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.AuthenticateAction.SIGN
                : software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.AuthenticateAction.DO_NOT_SIGN);
        }
        return schema;
    }

    private static boolean isSigned(String key) {
        // Signed test attributes: a (ENCRYPT_AND_SIGN), b (SIGN_ONLY), d (SIGN_AND_INCLUDE).
        return key.equals("a") || key.equals("b") || key.equals("d");
    }

    private static Map<String, StructuredDataTerminal> toPublishedTerminals(Map<String, Terminal> nativeMap) {
        Map<String, StructuredDataTerminal> out = new LinkedHashMap<>();
        nativeMap.forEach((key, terminal) -> out.put(key, StructuredDataTerminal.builder()
            .value(ByteBuffer.wrap(terminal.value()))
            .typeId(ByteBuffer.wrap(terminal.typeId()))
            .build()));
        return out;
    }

    private static Map<String, Terminal> toNativeTerminals(Map<String, StructuredDataTerminal> published) {
        Map<String, Terminal> out = new LinkedHashMap<>();
        published.forEach((key, terminal) ->
            out.put(key, new Terminal(toBytes(terminal.value()), toBytes(terminal.typeId()))));
        return out;
    }

    private static Map<String, byte[]> toByteMap(Map<String, String> context) {
        Map<String, byte[]> out = new LinkedHashMap<>();
        context.forEach((key, value) -> out.put(key, value.getBytes(StandardCharsets.UTF_8)));
        return out;
    }

    private static Map<String, String> toStringMap(Map<String, byte[]> context) {
        Map<String, String> out = new LinkedHashMap<>();
        context.forEach((key, value) -> out.put(key, new String(value, StandardCharsets.UTF_8)));
        return out;
    }

    private static Terminal nativeTerminal(String value) {
        return new Terminal(value.getBytes(StandardCharsets.UTF_8), TYPE_ID);
    }

    private static StructuredDataTerminal publishedTerminal(String value) {
        return StructuredDataTerminal.builder()
            .value(ByteBuffer.wrap(value.getBytes(StandardCharsets.UTF_8)))
            .typeId(ByteBuffer.wrap(TYPE_ID))
            .build();
    }

    private static byte[] toBytes(ByteBuffer buffer) {
        ByteBuffer duplicate = buffer.duplicate();
        byte[] bytes = new byte[duplicate.remaining()];
        duplicate.get(bytes);
        return bytes;
    }

    // The MPL encodes an EC private key as the signed big-endian scalar
    // (ECPrivateKey.getS().toByteArray()); reverse it back to a JCE key.
    private static PrivateKey decodePrivateKey(byte[] encoded) {
        try {
            return KeyFactory.getInstance("EC")
                .generatePrivate(new ECPrivateKeySpec(new BigInteger(encoded), p384Params()));
        } catch (Exception e) {
            throw new IllegalStateException("Could not decode EC private key", e);
        }
    }

    // The MPL encodes an EC public key as a SEC-1 compressed point; decompress
    // and rebuild the JCE key.
    private static PublicKey decodePublicKey(byte[] encoded) {
        try {
            ECParameterSpec params = p384Params();
            return KeyFactory.getInstance("EC")
                .generatePublic(new ECPublicKeySpec(decompressPoint(encoded, params), params));
        } catch (Exception e) {
            throw new IllegalStateException("Could not decode EC public key", e);
        }
    }

    private static ECPoint decompressPoint(byte[] encoded, ECParameterSpec params) {
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(encoded, 1, encoded.length));
        BigInteger yParity = switch (encoded[0]) {
            case 2 -> BigInteger.ZERO;
            case 3 -> BigInteger.ONE;
            default -> throw new IllegalStateException("Invalid compressed point prefix");
        };
        BigInteger p = ((ECFieldFp) params.getCurve().getField()).getP();
        BigInteger a = params.getCurve().getA();
        BigInteger b = params.getCurve().getB();
        BigInteger three = BigInteger.valueOf(3);
        BigInteger four = BigInteger.valueOf(4);
        // ySquared = x^3 + a*x + b (mod p); y = sqrt, valid because P-384's p ≡ 3 (mod 4).
        BigInteger ySquared = x.modPow(three, p).add(a.multiply(x).mod(p)).add(b).mod(p);
        BigInteger beta = ySquared.modPow(p.add(BigInteger.ONE).divide(four), p);
        BigInteger y = beta.mod(BigInteger.TWO).equals(yParity) ? beta : p.subtract(beta);
        return new ECPoint(x, y);
    }

    private static ECParameterSpec p384Params() {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp384r1"));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (Exception e) {
            throw new IllegalStateException("secp384r1 parameters unavailable", e);
        }
    }
}
