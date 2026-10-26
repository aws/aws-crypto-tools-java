package software.amazon.cryptography.dbesdk.examples;

import software.amazon.cryptography.dbesdk.dynamodbencryption.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbesdk.dynamodbencryption.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbesdk.dynamodbitemencryptor.DynamoDbItemEncryptorConfig;

public final class ConfigUtils {

  private ConfigUtils() {}

  public static DynamoDbItemEncryptorConfig fromEncryptionInterceptor(
    final DynamoDbEncryptionInterceptor encryptionInterceptor,
    final String tableName
  ) {
    final DynamoDbTableEncryptionConfig tableConfig = encryptionInterceptor
      .tableEncryptionConfigs()
      .get(tableName);

    final DynamoDbItemEncryptorConfig.Builder builder =
      DynamoDbItemEncryptorConfig
        .builder()
        .logicalTableName(tableConfig.logicalTableName())
        .partitionKeyName(tableConfig.partitionKeyName())
        .attributeActionsOnEncrypt(tableConfig.attributeActionsOnEncrypt())
        .algorithmSuiteId(tableConfig.algorithmSuiteId());

    // Copy each optional field only when the table config set it, so we never overwrite a builder
    // default with null.
    if (tableConfig.sortKeyName() != null) {
      builder.sortKeyName(tableConfig.sortKeyName());
    }
    if (tableConfig.allowedUnsignedAttributes() != null) {
      builder.allowedUnsignedAttributes(
        tableConfig.allowedUnsignedAttributes()
      );
    }
    if (tableConfig.allowedUnsignedAttributePrefix() != null) {
      builder.allowedUnsignedAttributePrefix(
        tableConfig.allowedUnsignedAttributePrefix()
      );
    }
    if (tableConfig.keyring() != null) {
      builder.keyring(tableConfig.keyring());
    }
    if (tableConfig.cmm() != null) {
      builder.cmm(tableConfig.cmm());
    }
    if (tableConfig.legacyOverride() != null) {
      builder.legacyOverride(tableConfig.legacyOverride());
    }
    if (tableConfig.plaintextOverride() != null) {
      builder.plaintextOverride(tableConfig.plaintextOverride());
    }
    return builder.build();
  }
}
