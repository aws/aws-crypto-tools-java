package software.amazon.cryptography.dbesdk.dynamodbencryption;

/**
 * Retrieves the raw beacon key for a branch-key id (Dafny {@code store.GetBeaconKey}). This
 * is the MPL boundary: the library depends on this narrow seam and never implements it; an
 * MPL-backed adapter (wrapping the key store's {@code GetBeaconKey}, which reads the branch
 * key from DynamoDB and unwraps it with KMS) supplies it at the integration layer.
 */
@FunctionalInterface
public interface BeaconKeyRetriever {

    /**
     * The raw beacon key material for {@code keyId}.
     *
     * @throws BeaconException if the key cannot be retrieved
     */
    byte[] getBeaconKey(String keyId);
}
