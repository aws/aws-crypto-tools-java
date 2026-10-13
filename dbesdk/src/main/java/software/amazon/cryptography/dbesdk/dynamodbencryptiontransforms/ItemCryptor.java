package software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms;

import java.util.Map;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

/**
 * The per-table item encrypt/decrypt capability the transforms middleware
 * composes over, mirroring the Dafny {@code itemEncryptor.EncryptItem} /
 * {@code .DecryptItem} call site.
 *
 * <p>It is an interface, not a concrete class, so the native library stays free
 * of any Material Providers Library dependency: the MPL-backed implementation
 * (which resolves a CMM to materials) is supplied by the caller. A failure is
 * raised as an unchecked exception; the transforms middleware lets it propagate.
 */
public interface ItemCryptor {

    /** Encrypt a plaintext DynamoDB item into its encrypted form. */
    Map<String, AttributeValue> encryptItem(Map<String, AttributeValue> plaintextItem);

    /** Decrypt an encrypted DynamoDB item back to plaintext. */
    Map<String, AttributeValue> decryptItem(Map<String, AttributeValue> encryptedItem);
}
