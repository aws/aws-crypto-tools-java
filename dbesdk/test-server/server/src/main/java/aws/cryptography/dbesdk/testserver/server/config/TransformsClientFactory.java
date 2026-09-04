package aws.cryptography.dbesdk.testserver.server.config;

import aws.cryptography.dbesdk.testserver.server.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.server.registry.RealTransformsClient;
import aws.cryptography.dbesdk.testserver.server.registry.TransformsClient;
import java.util.ArrayList;
import java.util.Map;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.model.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.model.DynamoDbTablesEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.transforms.DynamoDbEncryptionTransforms;
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
     * Build a transforms client bound to {@code tableName}.
     *
     * @throws RuntimeException if a real client cannot be constructed; the caller
     *     maps this to a {@code GenericServerError}.
     */
    public TransformsClient create(DBEClientConfig config, String tableName) {
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

        DynamoDbTablesEncryptionConfig tablesConfig = DynamoDbTablesEncryptionConfig.builder()
            .tableEncryptionConfigs(Map.of(tableName, table.build()))
            .build();

        DynamoDbEncryptionTransforms transforms = DynamoDbEncryptionTransforms.builder()
            .DynamoDbTablesEncryptionConfig(tablesConfig)
            .build();
        return new RealTransformsClient(transforms);
    }
}
