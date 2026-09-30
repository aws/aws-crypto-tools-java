package aws.cryptography.dbesdk.testserver.server.registry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import aws.cryptography.dbesdk.testserver.server.error.DbesdkClientException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.itemencryptor.DynamoDbItemEncryptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.itemencryptor.model.DecryptItemInput;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.itemencryptor.model.DynamoDbItemEncryptorConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.itemencryptor.model.EncryptItemInput;
import software.amazon.cryptography.dbesdk.dynamodbitemencryptor.ItemEncryptorConfig;
import software.amazon.cryptography.dbesdk.dynamodbitemencryptor.PlaintextOverride;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.model.CreateDefaultCryptographicMaterialsManagerInput;
import software.amazon.cryptography.materialproviders.model.CreateRawAesKeyringInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;

/**
 * Exercises the {@link NativeItemEncryptorClient} seam end to end through a real
 * MPL CMM (offline, Raw AES keyring). Correctness is proven by cross-decrypting
 * with the published Dafny {@link DynamoDbItemEncryptor} — the same library a peer
 * language server runs — in both directions, which is what {@code make orchestrate}
 * checks across the wire. The version-2 case (a SIGN_AND_INCLUDE attribute) proves
 * the seam composes the item base context with StructuredEncryption's version-2
 * contribution and marks the union required, or the two implementations would not
 * agree on the signature AAD.
 */
class NativeItemEncryptorClientSeamTest {

    private static final String TABLE = "table";
    private static final String PARTITION = "pk";

    private MaterialProviders materialProviders;
    private IKeyring keyring;
    private ICryptographicMaterialsManager cmm;

    @BeforeEach
    void setUp() {
        materialProviders = MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build()).build();
        byte[] wrappingKey = new byte[32];
        java.util.Arrays.fill(wrappingKey, (byte) 0x2a);
        keyring = materialProviders.CreateRawAesKeyring(CreateRawAesKeyringInput.builder()
            .keyNamespace("ns").keyName("key")
            .wrappingKey(ByteBuffer.wrap(wrappingKey))
            .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
            .build());
        cmm = materialProviders.CreateDefaultCryptographicMaterialsManager(
            CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(keyring).build());
    }

    @Test
    void nativeRoundTripV1() throws DbesdkClientException {
        NativeItemEncryptorClient client = nativeClient(v1Actions(), Set.of("plain"));
        Map<String, AttributeValue> encrypted = client.encryptItem(item());
        assertRecovered(client.decryptItem(encrypted));
    }

    @Test
    void nativeEncryptDafnyDecryptV1() throws DbesdkClientException {
        Map<String, AttributeValue> encrypted = nativeClient(v1Actions(), Set.of("plain")).encryptItem(item());
        assertRecovered(dafny(v1DafnyActions(), Set.of("plain"))
            .DecryptItem(DecryptItemInput.builder().encryptedItem(encrypted).build()).plaintextItem());
    }

    @Test
    void dafnyEncryptNativeDecryptV1() throws DbesdkClientException {
        Map<String, AttributeValue> encrypted = dafny(v1DafnyActions(), Set.of("plain"))
            .EncryptItem(EncryptItemInput.builder().plaintextItem(item()).build()).encryptedItem();
        assertRecovered(nativeClient(v1Actions(), Set.of("plain")).decryptItem(encrypted));
    }

    @Test
    void nativeEncryptDafnyDecryptV2() throws DbesdkClientException {
        // A SIGN_AND_INCLUDE partition key forces version 2; the key value is bound
        // in the encryption context via both the item base context and the V2 context.
        Map<String, CryptoAction> nativeActions = v1Actions();
        nativeActions.put(PARTITION, CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);
        Map<String, software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction> dafnyActions =
            v1DafnyActions();
        dafnyActions.put(PARTITION,
            software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT);

        Map<String, AttributeValue> encrypted = nativeClient(nativeActions, Set.of("plain")).encryptItem(item());
        assertRecovered(dafny(dafnyActions, Set.of("plain"))
            .DecryptItem(DecryptItemInput.builder().encryptedItem(encrypted).build()).plaintextItem());
    }

    @Test
    void forcePlaintextWriteIsPassthrough() throws DbesdkClientException {
        ItemEncryptorConfig config = ItemEncryptorConfig.builder()
            .logicalTableName(TABLE).partitionKeyName(PARTITION)
            .attributeActionsOnEncrypt(v1Actions())
            .allowedUnsignedAttributes(Set.of("plain"))
            .plaintextOverride(PlaintextOverride.FORCE_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ)
            .build();
        NativeItemEncryptorClient client = new NativeItemEncryptorClient(config, null, materialProviders, cmm);

        Map<String, AttributeValue> encrypted = client.encryptItem(item());
        assertEquals(item(), encrypted);
        assertFalse(encrypted.containsKey("aws_dbe_head"));
    }

    private NativeItemEncryptorClient nativeClient(Map<String, CryptoAction> actions, Set<String> allowedUnsigned) {
        ItemEncryptorConfig config = ItemEncryptorConfig.builder()
            .logicalTableName(TABLE).partitionKeyName(PARTITION)
            .attributeActionsOnEncrypt(actions)
            .allowedUnsignedAttributes(allowedUnsigned)
            .build();
        return new NativeItemEncryptorClient(config, null, materialProviders, cmm);
    }

    private DynamoDbItemEncryptor dafny(
            Map<String, software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction> actions,
            Set<String> allowedUnsigned) {
        return DynamoDbItemEncryptor.builder()
            .DynamoDbItemEncryptorConfig(DynamoDbItemEncryptorConfig.builder()
                .logicalTableName(TABLE).partitionKeyName(PARTITION)
                .attributeActionsOnEncrypt(actions)
                .allowedUnsignedAttributes(new ArrayList<>(allowedUnsigned))
                .keyring(keyring)
                .build())
            .build();
    }

    private static Map<String, CryptoAction> v1Actions() {
        Map<String, CryptoAction> actions = new LinkedHashMap<>();
        actions.put(PARTITION, CryptoAction.SIGN_ONLY);
        actions.put("enc", CryptoAction.ENCRYPT_AND_SIGN);
        actions.put("sign", CryptoAction.SIGN_ONLY);
        actions.put("plain", CryptoAction.DO_NOTHING);
        return actions;
    }

    private static Map<String, software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction>
            v1DafnyActions() {
        var actions = new LinkedHashMap<String,
            software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction>();
        actions.put(PARTITION,
            software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction.SIGN_ONLY);
        actions.put("enc",
            software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction.ENCRYPT_AND_SIGN);
        actions.put("sign",
            software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction.SIGN_ONLY);
        actions.put("plain",
            software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction.DO_NOTHING);
        return actions;
    }

    private static Map<String, AttributeValue> item() {
        Map<String, AttributeValue> item = new LinkedHashMap<>();
        item.put(PARTITION, AttributeValue.fromS("id-1"));
        item.put("enc", AttributeValue.fromS("secret"));
        item.put("sign", AttributeValue.fromN("7"));
        item.put("plain", AttributeValue.fromS("keep"));
        return item;
    }

    private static void assertRecovered(Map<String, AttributeValue> decrypted) {
        assertEquals(AttributeValue.fromS("id-1"), decrypted.get(PARTITION));
        assertEquals(AttributeValue.fromS("secret"), decrypted.get("enc"));
        assertEquals(AttributeValue.fromN("7"), decrypted.get("sign"));
        assertEquals(AttributeValue.fromS("keep"), decrypted.get("plain"));
    }
}
