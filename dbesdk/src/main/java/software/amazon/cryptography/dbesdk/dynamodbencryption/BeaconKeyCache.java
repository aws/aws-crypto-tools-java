package software.amazon.cryptography.dbesdk.dynamodbencryption;

import java.util.Map;
import java.util.Optional;

/**
 * Caches derived beacon HMAC keys by cache identifier (Dafny {@code ICryptographicMaterialsCache}
 * for beacon-key materials). The library depends on this narrow seam; an MPL-backed adapter
 * supplies it at the integration layer. The time-to-live check lives in
 * {@link KeyStoreBeaconKeySource} (per the beacon-key source's configured TTL), so this seam
 * only stores and returns an entry with its creation time.
 */
public interface BeaconKeyCache {

    /** A cached key map and the epoch-second time it was stored. */
    record CacheEntry(Map<String, byte[]> hmacKeys, long creationTimeSeconds) {}

    /** The cached entry for this identifier, or empty if none is stored. */
    Optional<CacheEntry> get(byte[] cacheIdentifier);

    /** Store the derived keys with their creation and expiry times (both epoch seconds). */
    void put(byte[] cacheIdentifier, Map<String, byte[]> hmacKeys, long creationTimeSeconds, long expiryTimeSeconds);
}
