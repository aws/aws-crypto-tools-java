package aws.cryptography.dbesdk.testserver.server.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.dbesdk.testserver.server.model.CryptoAction;
import aws.cryptography.dbesdk.testserver.server.model.DBEClientConfig;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ItemEncryptorFactoryTest {

    private static DBEClientConfig config(Map<String, CryptoAction> actions) {
        return DBEClientConfig.builder()
            .logicalTableName("t")
            .partitionKeyName("pk")
            .attributeActionsOnEncrypt(actions)
            .build();
    }

    @Test
    void addsSignOnlyForSignedBeaconsButNotTheVersionTag() {
        DBEClientConfig config = config(Map.of(
            "pk", CryptoAction.SIGN_ONLY, "enc", CryptoAction.ENCRYPT_AND_SIGN));

        Map<String, software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction> actions =
            ItemEncryptorFactory.augmentedActions(config, List.of("sig"));

        assertEquals(
            software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction.SIGN_ONLY,
            actions.get("sig"));
        assertEquals(
            software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction.ENCRYPT_AND_SIGN,
            actions.get("enc"));
        // The version tag is authenticated via the reserved aws_dbe_ prefix, not an action.
        assertFalse(actions.containsKey("aws_dbe_v_1"));
    }

    @Test
    void rejectsSignedBeaconNameAlreadyConfigured() {
        DBEClientConfig config = config(Map.of(
            "pk", CryptoAction.SIGN_ONLY, "dup", CryptoAction.ENCRYPT_AND_SIGN));

        assertThrows(IllegalArgumentException.class,
            () -> ItemEncryptorFactory.augmentedActions(config, List.of("dup")));
    }
}
