package software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms;

/** Raised when a DynamoDB transform cannot be applied. */
public class DynamoDbEncryptionTransformsException extends RuntimeException {

    public DynamoDbEncryptionTransformsException(String message) {
        super(message);
    }

    public DynamoDbEncryptionTransformsException(String message, Throwable cause) {
        super(message, cause);
    }
}
