package software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import software.amazon.cryptography.dbesdk.dynamodbitemencryptor.PlaintextOverride;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction;

/**
 * One table's transforms configuration: the names that identify its primary
 * key, its plaintext policy, its attribute actions, and the item cryptor that
 * encrypts/decrypts its items. Mirrors the Dafny transforms internal
 * {@code TableConfig}.
 *
 * <p>A table with no {@code search} config makes every beacon-support step a
 * no-op; a table with a {@code search} config runs the beacon write path.
 */
public final class TableConfig {

    private final String logicalTableName;
    private final String partitionKeyName;
    private final Optional<String> sortKeyName;
    private final PlaintextOverride plaintextOverride;
    private final Map<String, CryptoAction> attributeActionsOnEncrypt;
    private final ItemCryptor itemCryptor;
    private final Optional<SearchInfo> search;

    private TableConfig(Builder builder) {
        this.logicalTableName = Objects.requireNonNull(builder.logicalTableName, "logicalTableName");
        this.partitionKeyName = Objects.requireNonNull(builder.partitionKeyName, "partitionKeyName");
        this.sortKeyName = Optional.ofNullable(builder.sortKeyName);
        this.plaintextOverride = Objects.requireNonNull(builder.plaintextOverride, "plaintextOverride");
        this.attributeActionsOnEncrypt =
            Map.copyOf(Objects.requireNonNull(builder.attributeActionsOnEncrypt, "attributeActionsOnEncrypt"));
        this.itemCryptor = Objects.requireNonNull(builder.itemCryptor, "itemCryptor");
        this.search = Optional.ofNullable(builder.search);
    }

    public String logicalTableName() {
        return logicalTableName;
    }

    public String partitionKeyName() {
        return partitionKeyName;
    }

    public Optional<String> sortKeyName() {
        return sortKeyName;
    }

    public PlaintextOverride plaintextOverride() {
        return plaintextOverride;
    }

    public Map<String, CryptoAction> attributeActionsOnEncrypt() {
        return attributeActionsOnEncrypt;
    }

    public ItemCryptor itemCryptor() {
        return itemCryptor;
    }

    /** The table's searchable-encryption write path, if beacons are configured. */
    public Optional<SearchInfo> search() {
        return search;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String logicalTableName;
        private String partitionKeyName;
        private String sortKeyName;
        private PlaintextOverride plaintextOverride;
        private Map<String, CryptoAction> attributeActionsOnEncrypt;
        private ItemCryptor itemCryptor;
        private SearchInfo search;

        public Builder logicalTableName(String logicalTableName) {
            this.logicalTableName = logicalTableName;
            return this;
        }

        public Builder partitionKeyName(String partitionKeyName) {
            this.partitionKeyName = partitionKeyName;
            return this;
        }

        public Builder sortKeyName(String sortKeyName) {
            this.sortKeyName = sortKeyName;
            return this;
        }

        public Builder plaintextOverride(PlaintextOverride plaintextOverride) {
            this.plaintextOverride = plaintextOverride;
            return this;
        }

        public Builder attributeActionsOnEncrypt(Map<String, CryptoAction> attributeActionsOnEncrypt) {
            this.attributeActionsOnEncrypt = attributeActionsOnEncrypt;
            return this;
        }

        public Builder itemCryptor(ItemCryptor itemCryptor) {
            this.itemCryptor = itemCryptor;
            return this;
        }

        public Builder search(SearchInfo search) {
            this.search = search;
            return this;
        }

        public TableConfig build() {
            return new TableConfig(this);
        }
    }
}
