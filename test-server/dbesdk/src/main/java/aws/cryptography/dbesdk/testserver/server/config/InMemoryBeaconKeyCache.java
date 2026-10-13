package aws.cryptography.dbesdk.testserver.server.config;

import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import software.amazon.cryptography.dbesdk.dynamodbencryption.BeaconKeyCache;

/**
 * A process-local beacon-key cache. The time-to-live check lives in the native
 * {@code KeyStoreBeaconKeySource} (which compares against the stored creation time), so this
 * cache only stores and returns entries. The MPL cryptographic-materials cache is only
 * needed to share entries across key sources, which the conformance server does not do.
 */
final class InMemoryBeaconKeyCache implements BeaconKeyCache {

    private final Map<String, CacheEntry> entries = new ConcurrentHashMap<>();

    @Override
    public Optional<CacheEntry> get(byte[] cacheIdentifier) {
        return Optional.ofNullable(entries.get(HexFormat.of().formatHex(cacheIdentifier)));
    }

    @Override
    public void put(
            byte[] cacheIdentifier, Map<String, byte[]> hmacKeys, long creationTimeSeconds, long expiryTimeSeconds) {
        entries.put(HexFormat.of().formatHex(cacheIdentifier), new CacheEntry(hmacKeys, creationTimeSeconds));
    }
}
