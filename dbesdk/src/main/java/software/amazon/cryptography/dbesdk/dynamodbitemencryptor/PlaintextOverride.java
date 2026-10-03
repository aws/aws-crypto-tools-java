package software.amazon.cryptography.dbesdk.dynamodbitemencryptor;

/**
 * Whether items may be written/read in plaintext (DynamoDbItemEncryptor behavior
 * spec §2). The default when unspecified is {@code FORBID_PLAINTEXT_WRITE_FORBID_PLAINTEXT_READ}.
 */
public enum PlaintextOverride {
    FORBID_PLAINTEXT_WRITE_FORBID_PLAINTEXT_READ,
    FORBID_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ,
    FORCE_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ
}
