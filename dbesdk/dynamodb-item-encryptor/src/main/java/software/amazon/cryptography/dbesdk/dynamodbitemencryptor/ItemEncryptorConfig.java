package software.amazon.cryptography.dbesdk.dynamodbitemencryptor;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction;

/**
 * The MPL-free half of a DynamoDbItemEncryptor configuration and its validation
 * (DynamoDbItemEncryptor behavior spec §2). It carries the table/key names, the
 * per-attribute crypto actions, the unsigned-attribute allowances, and the
 * plaintext policy — everything needed to build encryption contexts and schemas
 * and to decide signature scope. The keyring/CMM, algorithm suite, and legacy
 * override (all MPL- or extern-typed) are resolved at the seam, not here.
 *
 * <p>The {@link Builder} validates on {@code build()} and derives the
 * configuration version from the actions.
 */
public final class ItemEncryptorConfig {

    // An attribute name may not be configured under either reserved namespace.
    private static final String DBE_RESERVED_PREFIX = "aws_dbe_";
    private static final String CRYPTO_RESERVED_PREFIX = "aws-crypto-";

    private final String logicalTableName;
    private final String partitionKeyName;
    private final String sortKeyName; // null when the table has no sort key
    private final Map<String, CryptoAction> attributeActionsOnEncrypt;
    private final Set<String> allowedUnsignedAttributes;
    private final String allowedUnsignedAttributePrefix; // null when unset
    private final PlaintextOverride plaintextOverride;
    private final int version;

    private ItemEncryptorConfig(Builder builder) {
        this.logicalTableName = builder.logicalTableName;
        this.partitionKeyName = builder.partitionKeyName;
        this.sortKeyName = builder.sortKeyName;
        this.attributeActionsOnEncrypt =
            Collections.unmodifiableMap(new LinkedHashMap<>(builder.attributeActionsOnEncrypt));
        this.allowedUnsignedAttributes =
            Collections.unmodifiableSet(new LinkedHashSet<>(builder.allowedUnsignedAttributes));
        this.allowedUnsignedAttributePrefix = builder.allowedUnsignedAttributePrefix;
        this.plaintextOverride = builder.plaintextOverride;
        this.version = deriveVersion(this.attributeActionsOnEncrypt);
    }

    public static Builder builder() {
        return new Builder();
    }

    public String logicalTableName() {
        return logicalTableName;
    }

    public String partitionKeyName() {
        return partitionKeyName;
    }

    /** The sort key name, or {@code null} when the table has no sort key. */
    public String sortKeyName() {
        return sortKeyName;
    }

    public Map<String, CryptoAction> attributeActionsOnEncrypt() {
        return attributeActionsOnEncrypt;
    }

    public PlaintextOverride plaintextOverride() {
        return plaintextOverride;
    }

    /** 2 if any action is SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT, else 1. */
    public int version() {
        return version;
    }

    /**
     * Whether an attribute is authenticated (signed). An attribute is out of
     * signature scope only if it is explicitly allowed unsigned, begins with the
     * configured unsigned prefix, or begins with the reserved {@code aws_dbe_} prefix.
     */
    public boolean inSignatureScope(String attribute) {
        return !allowedUnsigned(attribute);
    }

    private boolean allowedUnsigned(String attribute) {
        return allowedUnsignedAttributes.contains(attribute)
            || (allowedUnsignedAttributePrefix != null && attribute.startsWith(allowedUnsignedAttributePrefix))
            || attribute.startsWith(DBE_RESERVED_PREFIX);
    }

    private static int deriveVersion(Map<String, CryptoAction> actions) {
        return actions.containsValue(CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT) ? 2 : 1;
    }

    private static CryptoAction keyAction(int version) {
        return version == 2 ? CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT : CryptoAction.SIGN_ONLY;
    }

    private static boolean forwardCompatible(
            String attribute,
            CryptoAction action,
            Set<String> allowedUnsigned,
            String allowedUnsignedPrefix) {
        boolean unsigned = allowedUnsigned.contains(attribute)
            || (allowedUnsignedPrefix != null && attribute.startsWith(allowedUnsignedPrefix))
            || attribute.startsWith(DBE_RESERVED_PREFIX);
        return action == CryptoAction.DO_NOTHING ? unsigned : !unsigned;
    }

    private static String explainNotForwardCompatible(
            String attribute,
            CryptoAction action,
            Set<String> allowedUnsigned,
            String allowedUnsignedPrefix) {
        String because;
        if (action == CryptoAction.DO_NOTHING) {
            because = "it must also be in unauthenticatedAttributes or begin with the unauthenticatedPrefix.";
        } else if (allowedUnsigned.contains(attribute)) {
            because = "it is also in unauthenticatedAttributes.";
        } else if (allowedUnsignedPrefix != null && attribute.startsWith(allowedUnsignedPrefix)) {
            because = "it also begins with the unauthenticatedPrefix.";
        } else {
            because = "it also begins with the reserved prefix.";
        }
        return "Attribute " + attribute + " is configured as " + action + " but " + because;
    }

    public static final class Builder {
        private String logicalTableName;
        private String partitionKeyName;
        private String sortKeyName;
        private Map<String, CryptoAction> attributeActionsOnEncrypt = new LinkedHashMap<>();
        private Set<String> allowedUnsignedAttributes = new LinkedHashSet<>();
        private String allowedUnsignedAttributePrefix;
        private PlaintextOverride plaintextOverride = PlaintextOverride.FORBID_PLAINTEXT_WRITE_FORBID_PLAINTEXT_READ;

        private Builder() {}

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

        public Builder attributeActionsOnEncrypt(Map<String, CryptoAction> actions) {
            this.attributeActionsOnEncrypt = new LinkedHashMap<>(actions);
            return this;
        }

        public Builder allowedUnsignedAttributes(Set<String> allowedUnsignedAttributes) {
            this.allowedUnsignedAttributes = new LinkedHashSet<>(allowedUnsignedAttributes);
            return this;
        }

        public Builder allowedUnsignedAttributePrefix(String allowedUnsignedAttributePrefix) {
            this.allowedUnsignedAttributePrefix = allowedUnsignedAttributePrefix;
            return this;
        }

        public Builder plaintextOverride(PlaintextOverride plaintextOverride) {
            this.plaintextOverride = plaintextOverride;
            return this;
        }

        public ItemEncryptorConfig build() {
            Objects.requireNonNull(logicalTableName, "logicalTableName is required");
            Objects.requireNonNull(partitionKeyName, "partitionKeyName is required");
            Objects.requireNonNull(plaintextOverride, "plaintextOverride is required");
            validateActions();
            return new ItemEncryptorConfig(this);
        }

        private void validateActions() {
            int version = deriveVersion(attributeActionsOnEncrypt);
            CryptoAction keyAction = keyAction(version);
            requireKeyAction(partitionKeyName, keyAction, "Partition key");
            if (sortKeyName != null) {
                requireKeyAction(sortKeyName, keyAction, "Sort key");
            }
            for (Map.Entry<String, CryptoAction> entry : attributeActionsOnEncrypt.entrySet()) {
                String attribute = entry.getKey();
                CryptoAction action = entry.getValue();
                if (!forwardCompatible(attribute, action, allowedUnsignedAttributes, allowedUnsignedAttributePrefix)) {
                    throw new DynamoDbItemEncryptorException(explainNotForwardCompatible(
                        attribute, action, allowedUnsignedAttributes, allowedUnsignedAttributePrefix));
                }
                if (attribute.startsWith(DBE_RESERVED_PREFIX) || attribute.startsWith(CRYPTO_RESERVED_PREFIX)) {
                    throw new DynamoDbItemEncryptorException(
                        "Attribute: " + attribute + " is reserved, and may not be configured.");
                }
            }
        }

        private void requireKeyAction(String keyName, CryptoAction keyAction, String label) {
            if (attributeActionsOnEncrypt.get(keyName) != keyAction) {
                throw new DynamoDbItemEncryptorException(label + " attribute action MUST be " + keyAction);
            }
        }
    }
}
