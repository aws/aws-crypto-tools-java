package aws.cryptography.dbesdk.testserver.server.registry;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import aws.cryptography.dbesdk.testserver.server.error.DbesdkClientException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.StructuredEncryption;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.AuthenticateAction;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.DecryptStructureInput;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.StructuredDataTerminal;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.StructuredEncryptionConfig;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.model.CreateDefaultCryptographicMaterialsManagerInput;
import software.amazon.cryptography.materialproviders.model.CreateRawAesKeyringInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;

/**
 * Exercises the {@link NativeStructuredClient} seam end to end through a real MPL
 * CMM (offline, Raw AES keyring): the adapters, materials resolution from the
 * CMM, and — for a SIGN_AND_INCLUDE field — the version-2 context and
 * Required-Encryption-Context CMM wrapping. Correctness is proven by decrypting
 * the native output with the published Dafny library (the same library a peer
 * language server runs), which is what {@code make orchestrate} checks across the
 * wire. The native crypto itself is proven byte-for-byte against Dafny in the
 * native module's cross-decrypt parity suite; this test proves the seam.
 */
class NativeStructuredClientSeamTest {

    private static final String TABLE = "table";
    private static final byte[] STRING_TYPE = {0, 1};

    private ICryptographicMaterialsManager cmm;
    private StructuredEncryption dafny;
    private NativeStructuredClient client;

    @BeforeEach
    void setUp() {
        MaterialProviders materialProviders = MaterialProviders.builder()
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
        client = new NativeStructuredClient(materialProviders, cmm);
    }

    @Test
    void encryptStructureRoundTripsThroughNative() throws DbesdkClientException {
        Map<String, StructuredDataTerminal> encrypted =
            client.encryptStructure(TABLE, plaintext(), cryptoSchema());
        Map<String, StructuredDataTerminal> decrypted =
            client.decryptStructure(TABLE, encrypted, authenticateSchema(encrypted.keySet()));
        assertRecovered(decrypted);
    }

    @Test
    void encryptStructureDecryptsUnderDafny() throws DbesdkClientException {
        Map<String, StructuredDataTerminal> encrypted =
            client.encryptStructure(TABLE, plaintext(), cryptoSchema());
        assertRecovered(dafnyDecrypt(encrypted));
    }

    // The SIGN_AND_INCLUDE field forces version 2: the seam must build the V2
    // context and wrap the CMM in a Required-EC CMM, or Dafny's decrypt (which
    // rebuilds both) would not agree on the signature AAD.
    @Test
    void signAndIncludeEncryptStructureDecryptsUnderDafny() throws DbesdkClientException {
        Map<String, StructuredDataTerminal> plaintext = plaintext();
        plaintext.put("d", terminal("delta"));
        Map<String, CryptoAction> schema = cryptoSchema();
        schema.put("d", CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);

        Map<String, StructuredDataTerminal> decrypted =
            dafnyDecrypt(client.encryptStructure(TABLE, plaintext, schema));

        assertRecovered(decrypted);
        assertArrayEquals("delta".getBytes(StandardCharsets.UTF_8), bytes(decrypted.get("d").value()));
    }

    private Map<String, StructuredDataTerminal> dafnyDecrypt(Map<String, StructuredDataTerminal> encrypted) {
        return dafny.DecryptStructure(DecryptStructureInput.builder()
            .tableName(TABLE)
            .encryptedStructure(encrypted)
            .authenticateSchema(authenticateSchema(encrypted.keySet()))
            .cmm(cmm)
            .build()).plaintextStructure();
    }

    private static void assertRecovered(Map<String, StructuredDataTerminal> decrypted) {
        assertArrayEquals("alpha".getBytes(StandardCharsets.UTF_8), bytes(decrypted.get("a").value()));
        assertArrayEquals("bravo".getBytes(StandardCharsets.UTF_8), bytes(decrypted.get("b").value()));
        assertArrayEquals("charlie".getBytes(StandardCharsets.UTF_8), bytes(decrypted.get("c").value()));
    }

    private static Map<String, StructuredDataTerminal> plaintext() {
        Map<String, StructuredDataTerminal> map = new LinkedHashMap<>();
        map.put("a", terminal("alpha"));
        map.put("b", terminal("bravo"));
        map.put("c", terminal("charlie"));
        return map;
    }

    private static Map<String, CryptoAction> cryptoSchema() {
        Map<String, CryptoAction> schema = new LinkedHashMap<>();
        schema.put("a", CryptoAction.ENCRYPT_AND_SIGN);
        schema.put("b", CryptoAction.SIGN_ONLY);
        schema.put("c", CryptoAction.DO_NOTHING);
        return schema;
    }

    private static Map<String, AuthenticateAction> authenticateSchema(Set<String> keys) {
        Map<String, AuthenticateAction> schema = new LinkedHashMap<>();
        for (String key : keys) {
            boolean signed = key.equals("a") || key.equals("b") || key.equals("d");
            schema.put(key, signed ? AuthenticateAction.SIGN : AuthenticateAction.DO_NOT_SIGN);
        }
        return schema;
    }

    private static StructuredDataTerminal terminal(String value) {
        return StructuredDataTerminal.builder()
            .value(ByteBuffer.wrap(value.getBytes(StandardCharsets.UTF_8)))
            .typeId(ByteBuffer.wrap(STRING_TYPE))
            .build();
    }

    private static byte[] bytes(ByteBuffer buffer) {
        ByteBuffer duplicate = buffer.duplicate();
        byte[] out = new byte[duplicate.remaining()];
        duplicate.get(out);
        return out;
    }
}
