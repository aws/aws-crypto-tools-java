package software.amazon.cryptography.dbesdk.dynamodbencryption;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A beacon key source that retrieves a branch key from a key store, derives the per-beacon
 * HMAC keys, and caches the result (Dafny {@code KeySource} over {@code SingleLoc}/
 * {@code MultiLoc}, {@code getKeysCache}/{@code getKeyMaterials}).
 *
 * <p>The retrieval and cache are injected seams ({@link BeaconKeyRetriever},
 * {@link BeaconKeyCache}) so the library stays independent of the MPL key store; everything
 * else — the cache-identifier bytes, the per-source TTL check, and the HKDF derivation — is
 * computed here.
 */
public final class KeyStoreBeaconKeySource implements BeaconKeySource {

    /** Where the branch-key id comes from: a fixed id (single-tenant) or the query (multi-tenant). */
    public sealed interface KeyLocation permits KeyLocation.Single, KeyLocation.Multi {
        /** Single-tenant: a fixed branch-key id; a query must not supply its own. */
        record Single(String keyId) implements KeyLocation {}

        /** Multi-tenant: the branch-key id is taken from the query/item. */
        record Multi() implements KeyLocation {}
    }

    /** The retrieval environment shared by every lookup (the MPL-facing seams + cache keying). */
    public record Context(
        BeaconKeyRetriever retriever,
        BeaconKeyCache cache,
        long cacheTtlSeconds,
        byte[] partitionIdBytes,
        byte[] logicalKeyStoreNameBytes,
        Clock clock) {}

    // Cache-identifier framing bytes (MPL CacheConstants.dfy).
    private static final byte RESOURCE_ID_HIERARCHICAL_KEYRING = 0x02;
    private static final byte SCOPE_ID_SEARCHABLE_ENCRYPTION = 0x03;
    private static final byte NULL_BYTE = 0x00;

    private final KeyLocation location;
    private final List<String> beaconNames;
    private final Context context;

    public KeyStoreBeaconKeySource(KeyLocation location, List<String> beaconNames, Context context) {
        this.location = location;
        this.beaconNames = List.copyOf(beaconNames);
        this.context = context;
    }

    @Override
    public MaybeKeyMap getKeyMap(MaybeKeyId keyId) {
        return switch (location) {
            case KeyLocation.Single single -> {
                if (!(keyId instanceof MaybeKeyId.DontUse)) {
                    throw new BeaconException("Key ID should not be supplied with a single-tenant key store.");
                }
                yield new MaybeKeyMap.Keys(keysFor(single.keyId()));
            }
            case KeyLocation.Multi ignored -> switch (keyId) {
                case MaybeKeyId.DontUse d ->
                    throw new BeaconException("A key ID is required for a multi-tenant key store.");
                case MaybeKeyId.ShouldHave s -> new MaybeKeyMap.ShouldHaveKeys();
                case MaybeKeyId.Explicit explicit -> new MaybeKeyMap.Keys(keysFor(explicit.id()));
            };
        };
    }

    // Cached-or-retrieved HMAC keys for one branch-key id. A cache hit is used only while
    // within this source's TTL; otherwise the key is retrieved, derived, and re-cached.
    private Map<String, byte[]> keysFor(String keyId) {
        byte[] cacheId = cacheIdentifier(keyId);
        long now = context.clock().instant().getEpochSecond();
        Optional<BeaconKeyCache.CacheEntry> cached = context.cache().get(cacheId);
        if (cached.isPresent() && now - cached.get().creationTimeSeconds() <= context.cacheTtlSeconds()) {
            return cached.get().hmacKeys();
        }
        byte[] beaconKey = context.retriever().getBeaconKey(keyId);
        Map<String, byte[]> keys = BeaconKeyDerivation.deriveHmacKeys(beaconKey, beaconNames);
        context.cache().put(cacheId, keys, now, now + context.cacheTtlSeconds());
        return keys;
    }

    // SHA-384 of resourceId · NULL · scopeId · NULL · partitionId · NULL · logicalKeyStoreName
    // · NULL · utf8(keyId) (Dafny getKeyMaterials cache identifier).
    private byte[] cacheIdentifier(String keyId) {
        ByteArrayOutputStream identifier = new ByteArrayOutputStream();
        identifier.write(RESOURCE_ID_HIERARCHICAL_KEYRING);
        identifier.write(NULL_BYTE);
        identifier.write(SCOPE_ID_SEARCHABLE_ENCRYPTION);
        identifier.write(NULL_BYTE);
        identifier.writeBytes(context.partitionIdBytes());
        identifier.write(NULL_BYTE);
        identifier.writeBytes(context.logicalKeyStoreNameBytes());
        identifier.write(NULL_BYTE);
        identifier.writeBytes(keyId.getBytes(StandardCharsets.UTF_8));
        return sha384(identifier.toByteArray());
    }

    private static byte[] sha384(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-384").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new BeaconException("SHA-384 unavailable", e);
        }
    }
}
