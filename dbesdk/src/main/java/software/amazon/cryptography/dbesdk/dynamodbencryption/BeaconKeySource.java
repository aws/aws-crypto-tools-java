package software.amazon.cryptography.dbesdk.dynamodbencryption;

/**
 * The source of beacon HMAC keys for a beacon version (Dafny {@code KeySource.getKeyMap}).
 * Either keys configured directly ({@link LiteralBeaconKeySource}) or keys retrieved from a
 * key store and cached ({@link KeyStoreBeaconKeySource}).
 */
public sealed interface BeaconKeySource
    permits LiteralBeaconKeySource, KeyStoreBeaconKeySource {

    /**
     * Resolve the beacon HMAC keys for a query/item, given whether a key id is available.
     *
     * @throws BeaconException if a key id is supplied where none is allowed (or is required
     *     but absent)
     */
    MaybeKeyMap getKeyMap(MaybeKeyId keyId);
}
