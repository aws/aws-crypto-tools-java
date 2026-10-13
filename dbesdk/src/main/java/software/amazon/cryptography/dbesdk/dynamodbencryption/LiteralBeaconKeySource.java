package software.amazon.cryptography.dbesdk.dynamodbencryption;

import java.util.Map;

/**
 * A beacon key source whose keys are configured directly, with no key store (Dafny
 * {@code LiteralLoc}). A query key id must not be supplied with a literal source.
 */
public final class LiteralBeaconKeySource implements BeaconKeySource {

    private final Map<String, byte[]> keys;

    public LiteralBeaconKeySource(Map<String, byte[]> keys) {
        this.keys = Map.copyOf(keys);
    }

    @Override
    public MaybeKeyMap getKeyMap(MaybeKeyId keyId) {
        if (!(keyId instanceof MaybeKeyId.DontUse)) {
            throw new BeaconException("Key ID should not be supplied with a literal key store.");
        }
        return new MaybeKeyMap.Keys(keys);
    }
}
