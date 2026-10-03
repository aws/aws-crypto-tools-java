package software.amazon.cryptography.dbesdk.structuredencryption;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.AlgorithmSuite;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthItem;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthenticateAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoItem;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.DecryptionMaterials;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.EncryptedDataKey;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.EncryptionMaterials;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.ParsedHeader;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Path;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Terminal;

class StructuredEncryptionClientTest {

    private static final String TABLE = "table";
    private static final byte[] TYPE_ID = {0, 1};
    private static final byte[] DATA_KEY = filled((byte) 0x11, 32);
    private static final byte[] SIGNING_KEY = filled((byte) 0x22, 32);
    private static final byte[] BYTES_TYPE_ID = {(byte) 0xFF, (byte) 0xFF};

    private static List<CryptoItem> plaintext() {
        return List.of(
            new CryptoItem(Path.ofAttribute("a"), terminal("alpha"), CryptoAction.ENCRYPT_AND_SIGN),
            new CryptoItem(Path.ofAttribute("b"), terminal("bravo"), CryptoAction.SIGN_ONLY),
            new CryptoItem(Path.ofAttribute("c"), terminal("charlie"), CryptoAction.DO_NOTHING));
    }

    @Test
    void roundTripUnsignedSuiteRecoversPlaintext() {
        AlgorithmSuite suite = suite((byte) 0x00, false);
        List<CryptoItem> encrypted = StructuredEncryptionClient.encryptPathStructure(
            TABLE, plaintext(), encryptionMaterials(suite, null)).structure();

        List<CryptoItem> decrypted = StructuredEncryptionClient.decryptPathStructure(
            TABLE, authItemsFrom(encrypted), decryptionMaterials(suite, null)).structure();

        assertRecovered(decrypted);
    }

    @Test
    void roundTripSignedSuiteRecoversPlaintext() throws Exception {
        KeyPair keyPair = p384KeyPair();
        AlgorithmSuite suite = suite((byte) 0x01, true);

        List<CryptoItem> encrypted = StructuredEncryptionClient.encryptPathStructure(
            TABLE, plaintext(), encryptionMaterials(suite, keyPair)).structure();
        List<CryptoItem> decrypted = StructuredEncryptionClient.decryptPathStructure(
            TABLE, authItemsFrom(encrypted), decryptionMaterials(suite, keyPair)).structure();

        assertRecovered(decrypted);
    }

    @Test
    void encryptAppendsHeaderFooterAndOnlyEncryptsEncryptAndSign() {
        List<CryptoItem> encrypted = StructuredEncryptionClient.encryptPathStructure(
            TABLE, plaintext(), encryptionMaterials(suite((byte) 0x00, false), null)).structure();

        assertEquals(5, encrypted.size());
        assertEquals("aws_dbe_head", encrypted.get(3).key().segments().get(0));
        assertEquals("aws_dbe_foot", encrypted.get(4).key().segments().get(0));

        Map<String, Terminal> byName = byName(encrypted);
        // "a" is ENCRYPT_AND_SIGN: type id becomes 0xFFFF and the value changes.
        assertArrayEquals(BYTES_TYPE_ID, byName.get("a").typeId());
        assertFalse(Arrays.equals("alpha".getBytes(StandardCharsets.UTF_8), byName.get("a").value()));
        // "c" is DO_NOTHING: passed through unchanged.
        assertArrayEquals("charlie".getBytes(StandardCharsets.UTF_8), byName.get("c").value());
        assertArrayEquals(TYPE_ID, byName.get("c").typeId());
    }

    @Test
    void encryptRejectsAllDoNothingSchema() {
        List<CryptoItem> allDoNothing = List.of(
            new CryptoItem(Path.ofAttribute("a"), terminal("alpha"), CryptoAction.DO_NOTHING));

        StructuredEncryptionException thrown = assertThrows(
            StructuredEncryptionException.class,
            () -> StructuredEncryptionClient.encryptPathStructure(
                TABLE, allDoNothing, encryptionMaterials(suite((byte) 0x00, false), null)));
        assertEquals(
            "At least one field in the Crypto Schema must be ENCRYPT_AND_SIGN, "
                + "SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT or SIGN_ONLY.",
            thrown.getMessage());
    }

    @Test
    void resolveAuthActionsRecoversActionsFromHeaderLegend() {
        List<CryptoItem> encrypted = StructuredEncryptionClient.encryptPathStructure(
            TABLE, plaintext(), encryptionMaterials(suite((byte) 0x00, false), null)).structure();
        byte[] headerBytes = byName(encrypted).get("aws_dbe_head").value();

        List<CryptoItem> resolved = StructuredEncryptionClient.resolveAuthActions(
            TABLE, authItemsFrom(encrypted), headerBytes);

        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        for (CryptoItem item : resolved) {
            actions.put(item.key().segments().get(0), item.action());
        }
        assertEquals(CryptoAction.ENCRYPT_AND_SIGN, actions.get("a"));
        assertEquals(CryptoAction.SIGN_ONLY, actions.get("b"));
        assertEquals(CryptoAction.DO_NOTHING, actions.get("c"));
    }

    @Test
    void mapStructureRoundTripRecoversPlaintext() {
        AlgorithmSuite suite = suite((byte) 0x00, false);
        Map<String, Terminal> plaintextStructure = new LinkedHashMap<>();
        plaintextStructure.put("a", terminal("alpha"));
        plaintextStructure.put("b", terminal("bravo"));
        plaintextStructure.put("c", terminal("charlie"));
        Map<String, CryptoAction> cryptoSchema = new LinkedHashMap<>();
        cryptoSchema.put("a", CryptoAction.ENCRYPT_AND_SIGN);
        cryptoSchema.put("b", CryptoAction.SIGN_ONLY);
        cryptoSchema.put("c", CryptoAction.DO_NOTHING);

        MapStructureOutput encryptOutput = StructuredEncryptionClient.encryptStructure(
            TABLE, plaintextStructure, cryptoSchema, encryptionMaterials(suite, null));
        Map<String, Terminal> encrypted = encryptOutput.structure();
        // The reserved fields are present in the encrypted map.
        assertEquals(Set.of("a", "b", "c", "aws_dbe_head", "aws_dbe_foot"), encrypted.keySet());
        // cryptoSchema carries only the authenticated fields (DO_NOTHING "c" and the
        // reserved header/footer are excluded).
        assertEquals(
            Map.of("a", CryptoAction.ENCRYPT_AND_SIGN, "b", CryptoAction.SIGN_ONLY),
            encryptOutput.cryptoSchema());

        Map<String, AuthenticateAction> authenticateSchema = new LinkedHashMap<>();
        authenticateSchema.put("a", AuthenticateAction.SIGN);
        authenticateSchema.put("b", AuthenticateAction.SIGN);
        authenticateSchema.put("c", AuthenticateAction.DO_NOT_SIGN);
        authenticateSchema.put("aws_dbe_head", AuthenticateAction.DO_NOT_SIGN);
        authenticateSchema.put("aws_dbe_foot", AuthenticateAction.DO_NOT_SIGN);

        MapStructureOutput decryptOutput = StructuredEncryptionClient.decryptStructure(
            TABLE, encrypted, authenticateSchema, decryptionMaterials(suite, null));
        Map<String, Terminal> decrypted = decryptOutput.structure();

        assertEquals(Set.of("a", "b", "c"), decrypted.keySet());
        assertArrayEquals("alpha".getBytes(StandardCharsets.UTF_8), decrypted.get("a").value());
        assertArrayEquals("bravo".getBytes(StandardCharsets.UTF_8), decrypted.get("b").value());
        assertArrayEquals("charlie".getBytes(StandardCharsets.UTF_8), decrypted.get("c").value());
        // Decrypt recovers each authenticated field's action from the header legend.
        assertEquals(
            Map.of("a", CryptoAction.ENCRYPT_AND_SIGN, "b", CryptoAction.SIGN_ONLY),
            decryptOutput.cryptoSchema());
    }

    @Test
    void encryptStructureRejectsMismatchedKeys() {
        StructuredEncryptionException thrown = assertThrows(
            StructuredEncryptionException.class,
            () -> StructuredEncryptionClient.encryptStructure(
                TABLE,
                Map.of("a", terminal("alpha")),
                Map.of("b", CryptoAction.ENCRYPT_AND_SIGN),
                encryptionMaterials(suite((byte) 0x00, false), null)));
        assertEquals("Crypto Keys don't match.", thrown.getMessage());
    }

    @Test
    void decryptStructureRejectsMismatchedKeys() {
        StructuredEncryptionException thrown = assertThrows(
            StructuredEncryptionException.class,
            () -> StructuredEncryptionClient.decryptStructure(
                TABLE,
                Map.of("a", terminal("alpha")),
                Map.of("b", AuthenticateAction.SIGN),
                decryptionMaterials(suite((byte) 0x00, false), null)));
        assertEquals(
            "DecryptStructure requires encryptedStructure and authenticateSchema have the same keys.",
            thrown.getMessage());
    }

    @Test
    void parsedHeaderReportsStoredAndFullContext() {
        AlgorithmSuite suite = suite((byte) 0x00, false);
        // A Required-EC CMM would hold the aws-crypto-* keys out of the stored
        // header while binding them in the signature; "plain" is an ordinary entry.
        Map<String, byte[]> fullContext = new LinkedHashMap<>();
        fullContext.put("plain", "p".getBytes(StandardCharsets.UTF_8));
        fullContext.put("aws-crypto-attr.d", "delta".getBytes(StandardCharsets.UTF_8));
        fullContext.put("aws-crypto-legend", "S".getBytes(StandardCharsets.UTF_8));
        Set<String> required = Set.of("aws-crypto-attr.d", "aws-crypto-legend");
        EncryptionMaterials materials = new EncryptionMaterials(
            DATA_KEY, suite,
            List.of(new EncryptedDataKey("prov".getBytes(StandardCharsets.UTF_8), new byte[0], new byte[] {1, 2, 3})),
            fullContext, required, List.of(SIGNING_KEY), null);
        List<CryptoItem> plaintext = List.of(
            new CryptoItem(Path.ofAttribute("a"), terminal("alpha"), CryptoAction.ENCRYPT_AND_SIGN),
            new CryptoItem(Path.ofAttribute("d"), terminal("delta"),
                CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT));

        PathStructureOutput encrypted =
            StructuredEncryptionClient.encryptPathStructure(TABLE, plaintext, materials);
        ParsedHeader encryptHeader = encrypted.parsedHeader();

        assertEquals(fullContext.keySet(), encryptHeader.encryptionContext().keySet());
        assertEquals(Set.of("plain"), encryptHeader.storedEncryptionContext().keySet());
        assertArrayEquals("p".getBytes(StandardCharsets.UTF_8), encryptHeader.storedEncryptionContext().get("plain"));
        assertEquals(suite, encryptHeader.algorithmSuite());
        assertEquals(1, encryptHeader.encryptedDataKeys().size());

        // On decrypt the stored context is what the header carried; the full context
        // is what the caller supplied (and the signature was verified against).
        DecryptionMaterials decryptionMaterials =
            new DecryptionMaterials(DATA_KEY, suite, fullContext, SIGNING_KEY, null);
        List<AuthItem> auth = authItemsFrom(encrypted.structure());
        ParsedHeader decryptHeader = StructuredEncryptionClient.decryptPathStructure(
            TABLE, auth, decryptionMaterials).parsedHeader();

        assertEquals(Set.of("plain"), decryptHeader.storedEncryptionContext().keySet());
        assertEquals(fullContext.keySet(), decryptHeader.encryptionContext().keySet());
    }

    private static void assertRecovered(List<CryptoItem> decrypted) {
        Map<String, Terminal> byName = byName(decrypted);
        assertEquals(Set.of("a", "b", "c"), byName.keySet());
        assertArrayEquals("alpha".getBytes(StandardCharsets.UTF_8), byName.get("a").value());
        assertArrayEquals(TYPE_ID, byName.get("a").typeId());
        assertArrayEquals("bravo".getBytes(StandardCharsets.UTF_8), byName.get("b").value());
        assertArrayEquals("charlie".getBytes(StandardCharsets.UTF_8), byName.get("c").value());
    }

    // Mirror an authenticate schema: a field signed on encrypt is marked SIGN,
    // a DO_NOTHING field (and the reserved header/footer) DO_NOT_SIGN.
    private static List<AuthItem> authItemsFrom(List<CryptoItem> encrypted) {
        List<AuthItem> auth = new ArrayList<>(encrypted.size());
        for (CryptoItem item : encrypted) {
            AuthenticateAction action = item.action() == CryptoAction.DO_NOTHING
                ? AuthenticateAction.DO_NOT_SIGN
                : AuthenticateAction.SIGN;
            auth.add(new AuthItem(item.key(), item.data(), action));
        }
        return auth;
    }

    private static AlgorithmSuite suite(byte flavor, boolean hasEcdsa) {
        return new AlgorithmSuite(flavor, hasEcdsa, "HmacSHA512", "HmacSHA512", "HmacSHA384", 32, 32);
    }

    private static EncryptionMaterials encryptionMaterials(AlgorithmSuite suite, KeyPair keyPair) {
        return new EncryptionMaterials(
            DATA_KEY, suite,
            List.of(new EncryptedDataKey("prov".getBytes(StandardCharsets.UTF_8), new byte[0], new byte[] {1, 2, 3})),
            Map.of(), Set.of(), List.of(SIGNING_KEY),
            keyPair == null ? null : keyPair.getPrivate());
    }

    private static DecryptionMaterials decryptionMaterials(AlgorithmSuite suite, KeyPair keyPair) {
        return new DecryptionMaterials(
            DATA_KEY, suite, Map.of(), SIGNING_KEY,
            keyPair == null ? null : keyPair.getPublic());
    }

    private static Map<String, Terminal> byName(List<CryptoItem> items) {
        Map<String, Terminal> byName = new LinkedHashMap<>();
        for (CryptoItem item : items) {
            byName.put(item.key().segments().get(0), item.data());
        }
        return byName;
    }

    private static Terminal terminal(String value) {
        return new Terminal(value.getBytes(StandardCharsets.UTF_8), TYPE_ID);
    }

    private static byte[] filled(byte value, int length) {
        byte[] out = new byte[length];
        Arrays.fill(out, value);
        return out;
    }

    private static KeyPair p384KeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        return generator.generateKeyPair();
    }
}
