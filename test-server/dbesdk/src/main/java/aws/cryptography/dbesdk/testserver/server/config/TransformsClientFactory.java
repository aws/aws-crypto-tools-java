package aws.cryptography.dbesdk.testserver.server.config;

import aws.cryptography.dbesdk.testserver.server.error.DbesdkClientException;
import aws.cryptography.dbesdk.testserver.server.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.server.registry.DbesdkClient;
import aws.cryptography.dbesdk.testserver.server.registry.NativeTransformsClient;
import aws.cryptography.dbesdk.testserver.server.registry.TransformsClient;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms.DynamoDbEncryptionTransforms;
import software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms.ItemCryptor;
import software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms.SearchInfo;
import software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms.TableConfig;
import software.amazon.cryptography.dbesdk.dynamodbitemencryptor.PlaintextOverride;

/**
 * Builds a {@link NativeTransformsClient} over the native (non-Dafny)
 * {@link DynamoDbEncryptionTransforms}. Each modeled {@link DBEClientConfig} is
 * translated into a native {@link TableConfig}; its per-table item cryptor wraps
 * a native item encryptor built by {@link ItemEncryptorFactory} (so a transforms
 * client and an item-encryptor client built from the same config share identical
 * materials). When the config carries searchable-encryption config, the beacon write
 * path is built by {@link SearchInfoFactory} (key material from the MPL key store).
 */
public final class TransformsClientFactory {

    private final ItemEncryptorFactory materials;

    public TransformsClientFactory(ItemEncryptorFactory materials) {
        this.materials = materials;
    }

    /**
     * Build a transforms client bound to one or more tables, keyed by physical
     * table name.
     *
     * @throws RuntimeException if a real client cannot be constructed; the caller
     *     maps this to a {@code GenericServerError}.
     */
    public TransformsClient create(Map<String, DBEClientConfig> tables) {
        Map<String, TableConfig> tableConfigs = new LinkedHashMap<>();
        for (Map.Entry<String, DBEClientConfig> entry : tables.entrySet()) {
            tableConfigs.put(entry.getKey(), buildTableConfig(entry.getValue()));
        }
        return new NativeTransformsClient(new DynamoDbEncryptionTransforms(tableConfigs));
    }

    private TableConfig buildTableConfig(DBEClientConfig config) {
        SearchInfo search = config.getSearch() != null ? SearchInfoFactory.create(config.getSearch()) : null;
        List<String> signedBeaconNames = search != null ? search.signedBeaconNames() : List.of();
        DbesdkClient itemEncryptor = materials.create(config, signedBeaconNames);
        TableConfig.Builder table = TableConfig.builder()
            .logicalTableName(config.getLogicalTableName())
            .partitionKeyName(config.getPartitionKeyName())
            .attributeActionsOnEncrypt(ItemEncryptorFactory.augmentedActions(config, signedBeaconNames))
            .plaintextOverride(toNativePlaintextOverride(config.getPlaintextOverride()))
            .itemCryptor(itemCryptorOver(itemEncryptor));
        if (config.getSortKeyName() != null) {
            table.sortKeyName(config.getSortKeyName());
        }
        if (search != null) {
            table.search(search);
        }
        return table.build();
    }

    // Bridges the checked-exception item-encryptor interface to the unchecked
    // ItemCryptor seam, preserving the underlying message so the operation
    // wrapper still forwards it verbatim.
    private static ItemCryptor itemCryptorOver(DbesdkClient itemEncryptor) {
        return new ItemCryptor() {
            @Override
            public Map<String, AttributeValue> encryptItem(Map<String, AttributeValue> item) {
                try {
                    return itemEncryptor.encryptItem(item);
                } catch (DbesdkClientException failure) {
                    throw new RuntimeException(failure.getMessage(), failure);
                }
            }

            @Override
            public Map<String, AttributeValue> decryptItem(Map<String, AttributeValue> item) {
                try {
                    return itemEncryptor.decryptItem(item);
                } catch (DbesdkClientException failure) {
                    throw new RuntimeException(failure.getMessage(), failure);
                }
            }
        };
    }

    private static PlaintextOverride toNativePlaintextOverride(
            aws.cryptography.dbesdk.testserver.server.model.PlaintextOverride modeled) {
        if (modeled == null) {
            return PlaintextOverride.FORBID_PLAINTEXT_WRITE_FORBID_PLAINTEXT_READ;
        }
        return PlaintextOverride.valueOf(modeled.getValue());
    }
}
