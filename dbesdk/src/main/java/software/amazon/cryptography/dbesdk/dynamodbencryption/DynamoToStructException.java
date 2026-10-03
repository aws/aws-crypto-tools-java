package software.amazon.cryptography.dbesdk.dynamodbencryption;

/**
 * Signals a DynamoDB attribute (de)serialization failure — an invalid number, a
 * malformed encoded structure, a set with duplicates, or a value outside the
 * supported bounds (DynamoToStruct behavior spec §5, §7).
 */
public class DynamoToStructException extends RuntimeException {

    public DynamoToStructException(String message) {
        super(message);
    }
}
