package software.amazon.cryptography.dbesdk.dynamodbencryption;

import java.util.Map;

/**
 * The outcome of resolving beacon HMAC keys (Dafny {@code MaybeKeyMap}): the per-beacon
 * keys ({@link Keys}), the keyless path where beacons are computed as plaintext
 * ({@link DontUseKeys}, the "naked" value), or a query-planning marker that a key id is
 * required but not yet resolved ({@link ShouldHaveKeys}).
 */
public sealed interface MaybeKeyMap
    permits MaybeKeyMap.Keys, MaybeKeyMap.DontUseKeys, MaybeKeyMap.ShouldHaveKeys {

    record Keys(Map<String, byte[]> keys) implements MaybeKeyMap {
        public Keys {
            keys = Map.copyOf(keys);
        }
    }

    record DontUseKeys() implements MaybeKeyMap {}

    record ShouldHaveKeys() implements MaybeKeyMap {}
}
