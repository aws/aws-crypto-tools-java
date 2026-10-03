package software.amazon.cryptography.dbesdk.dynamodbitemencryptor;

/**
 * Signals a DynamoDbItemEncryptor failure — an invalid configuration, a missing
 * key attribute, an attribute with no configured action, or an unexpected header
 * version (DynamoDbItemEncryptor behavior spec §2–§5).
 */
public class DynamoDbItemEncryptorException extends RuntimeException {

    public DynamoDbItemEncryptorException(String message) {
        super(message);
    }
}
