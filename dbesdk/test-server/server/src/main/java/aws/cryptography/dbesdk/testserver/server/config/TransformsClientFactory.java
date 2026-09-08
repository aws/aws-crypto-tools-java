package aws.cryptography.dbesdk.testserver.server.config;

import aws.cryptography.dbesdk.testserver.server.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.server.registry.RealTransformsClient;
import aws.cryptography.dbesdk.testserver.server.registry.TransformsClient;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.model.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.model.DynamoDbTablesEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.transforms.DynamoDbEncryptionTransforms;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.model.BeaconKeySource;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.model.BeaconVersion;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.model.SearchConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.model.SingleKeyStore;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.model.StandardBeacon;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.KMSConfiguration;
import software.amazon.cryptography.keystore.model.KeyStoreConfig;
import software.amazon.cryptography.materialproviders.model.DBEAlgorithmSuiteId;

/**
 * Translates a validated {@link DBEClientConfig} plus a physical table name
 * into a {@link RealTransformsClient} backed by a real
 * {@link DynamoDbEncryptionTransforms}. The transforms client is built from a
 * {@link DynamoDbTablesEncryptionConfig} with a single entry keyed by the
 * physical table name, whose per-table crypto config carries the same fields as
 * the item encryptor's config.
 *
 * <p>The keyring / CMM and Crypto Action mapping are reused verbatim from
 * {@link ItemEncryptorFactory}, so a transforms client and an item encryptor
 * built from the same {@code DBEClientConfig} share identical materials. Only
 * the target config type differs ({@code DynamoDbTableEncryptionConfig} rather
 * than {@code DynamoDbItemEncryptorConfig}), which is why the scalar fields are
 * copied here rather than shared.
 */
public final class TransformsClientFactory {

    private final ItemEncryptorFactory materials;

    public TransformsClientFactory(ItemEncryptorFactory materials) {
        this.materials = materials;
    }

    /**
     * Build a transforms client bound to one or more tables. The
     * {@code tables} map is (physical table name → its crypto config); each
     * entry becomes an independent {@link DynamoDbTableEncryptionConfig} in the
     * {@link DynamoDbTablesEncryptionConfig}, so per-table settings (notably
     * {@code algorithmSuiteId}) do not leak across tables.
     *
     * @throws RuntimeException if a real client cannot be constructed; the caller
     *     maps this to a {@code GenericServerError}.
     */
    public TransformsClient create(Map<String, DBEClientConfig> tables) {
        Map<String, DynamoDbTableEncryptionConfig> tableConfigs = new LinkedHashMap<>();
        for (Map.Entry<String, DBEClientConfig> entry : tables.entrySet()) {
            tableConfigs.put(entry.getKey(), buildTableConfig(entry.getValue()));
        }

        DynamoDbTablesEncryptionConfig tablesConfig = DynamoDbTablesEncryptionConfig.builder()
            .tableEncryptionConfigs(tableConfigs)
            .build();

        DynamoDbEncryptionTransforms transforms = DynamoDbEncryptionTransforms.builder()
            .DynamoDbTablesEncryptionConfig(tablesConfig)
            .build();
        return new RealTransformsClient(transforms);
    }

    /** Build one table's {@link DynamoDbTableEncryptionConfig} from its config. */
    private DynamoDbTableEncryptionConfig buildTableConfig(DBEClientConfig config) {
        DynamoDbTableEncryptionConfig.Builder table = DynamoDbTableEncryptionConfig.builder()
            .logicalTableName(config.getLogicalTableName())
            .partitionKeyName(config.getPartitionKeyName())
            .attributeActionsOnEncrypt(
                ItemEncryptorFactory.toCryptoActions(config.getAttributeActionsOnEncrypt()));

        if (config.getSortKeyName() != null) {
            table.sortKeyName(config.getSortKeyName());
        }
        if (config.getAllowedUnsignedAttributePrefix() != null) {
            table.allowedUnsignedAttributePrefix(config.getAllowedUnsignedAttributePrefix());
        }
        if (config.hasAllowedUnsignedAttributes()
                && !config.getAllowedUnsignedAttributes().isEmpty()) {
            table.allowedUnsignedAttributes(new ArrayList<>(config.getAllowedUnsignedAttributes()));
        }
        if (config.getAlgorithmSuiteId() != null) {
            table.algorithmSuiteId(
                DBEAlgorithmSuiteId.valueOf(config.getAlgorithmSuiteId().getValue()));
        }

        // Exactly one of keyring / cmm is set (validated upstream), reusing the
        // item encryptor's recursive materials construction.
        if (config.getKeyring() != null) {
            table.keyring(materials.buildKeyring(config.getKeyring()));
        } else {
            table.cmm(materials.buildCmm(config.getCmm()));
        }

        if (config.getSearch() != null) {
            table.search(buildSearchConfig(config.getSearch()));
        }

        return table.build();
    }

    /**
     * Build a DBE {@link SearchConfig} (beacons) from the modeled config. The
     * beacon key store's DynamoDB and KMS clients are derived from the KMS key
     * ARN's region (no explicit clients), so the key store reaches
     * {@code KeyStoreDdbTable} with the ambient credentials.
     */
    private static SearchConfig buildSearchConfig(
            aws.cryptography.dbesdk.testserver.server.model.SearchConfig search) {
        List<BeaconVersion> versions = new ArrayList<>();
        for (aws.cryptography.dbesdk.testserver.server.model.BeaconVersion v
                : search.getVersions()) {
            aws.cryptography.dbesdk.testserver.server.model.BeaconKeyStore ks = v.getKeyStore();
            KeyStore keyStore = KeyStore.builder()
                .KeyStoreConfig(KeyStoreConfig.builder()
                    .ddbTableName(ks.getDdbTableName())
                    .logicalKeyStoreName(ks.getLogicalKeyStoreName())
                    .kmsConfiguration(KMSConfiguration.builder()
                        .kmsKeyArn(ks.getKmsKeyArn())
                        .build())
                    .build())
                .build();

            aws.cryptography.dbesdk.testserver.server.model.SingleKeyStore single =
                v.getKeySource().getSingle();
            if (single == null) {
                throw new IllegalArgumentException(
                    "BeaconKeySource requires a single key store");
            }
            BeaconKeySource keySource = BeaconKeySource.builder()
                .single(SingleKeyStore.builder()
                    .keyId(single.getKeyId())
                    .cacheTTL(single.getCacheTtlSeconds())
                    .build())
                .build();

            BeaconVersion.Builder bv = BeaconVersion.builder()
                .version(v.getVersion())
                .keyStore(keyStore)
                .keySource(keySource);
            if (v.getStandardBeacons() != null && !v.getStandardBeacons().isEmpty()) {
                List<StandardBeacon> beacons = new ArrayList<>();
                for (aws.cryptography.dbesdk.testserver.server.model.StandardBeacon b
                        : v.getStandardBeacons()) {
                    beacons.add(StandardBeacon.builder()
                        .name(b.getName())
                        .length(b.getLength())
                        .build());
                }
                bv.standardBeacons(beacons);
            }
            versions.add(bv.build());
        }
        return SearchConfig.builder()
            .versions(versions)
            .writeVersion(search.getWriteVersion() != null ? search.getWriteVersion() : 1)
            .build();
    }
}
