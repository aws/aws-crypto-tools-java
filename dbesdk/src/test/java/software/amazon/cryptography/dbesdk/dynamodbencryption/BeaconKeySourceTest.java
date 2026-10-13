package software.amazon.cryptography.dbesdk.dynamodbencryption;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class BeaconKeySourceTest {

    private static final List<String> BEACON_NAMES = List.of("b1", "b2");
    private static final byte[] RAW_KEY = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
    private static final byte[] PARTITION = "part".getBytes(StandardCharsets.UTF_8);
    private static final byte[] LOGICAL = "logical".getBytes(StandardCharsets.UTF_8);
    private static final long TTL_SECONDS = 100;

    @Test
    void literalReturnsConfiguredKeysAndRejectsAKeyId() {
        LiteralBeaconKeySource source = new LiteralBeaconKeySource(Map.of("b1", RAW_KEY));

        assertInstanceOf(MaybeKeyMap.Keys.class, source.getKeyMap(new MaybeKeyId.DontUse()));
        assertThrows(BeaconException.class, () -> source.getKeyMap(new MaybeKeyId.Explicit("x")));
    }

    @Test
    void singleTenantDerivesKeysThenServesFromCacheWithinTtl() {
        CountingRetriever retriever = new CountingRetriever(RAW_KEY);
        InMemoryCache cache = new InMemoryCache();
        KeyStoreBeaconKeySource source = new KeyStoreBeaconKeySource(
            new KeyStoreBeaconKeySource.KeyLocation.Single("key1"), BEACON_NAMES,
            context(retriever, cache, new MutableClock(1000)));

        MaybeKeyMap first = source.getKeyMap(new MaybeKeyId.DontUse());
        source.getKeyMap(new MaybeKeyId.DontUse());

        Map<String, byte[]> keys = assertInstanceOf(MaybeKeyMap.Keys.class, first).keys();
        assertArrayEquals(BeaconKeyDerivation.deriveBeaconKey(RAW_KEY, "b1"), keys.get("b1"));
        assertArrayEquals(BeaconKeyDerivation.deriveBeaconKey(RAW_KEY, "b2"), keys.get("b2"));
        assertEquals(1, retriever.calls, "second lookup within TTL must hit the cache");
    }

    @Test
    void singleTenantRejectsASuppliedKeyId() {
        KeyStoreBeaconKeySource source = new KeyStoreBeaconKeySource(
            new KeyStoreBeaconKeySource.KeyLocation.Single("key1"), BEACON_NAMES,
            context(new CountingRetriever(RAW_KEY), new InMemoryCache(), new MutableClock(1000)));

        assertThrows(BeaconException.class, () -> source.getKeyMap(new MaybeKeyId.Explicit("x")));
    }

    @Test
    void multiTenantDispatchesOnTheKeyIdTriState() {
        KeyStoreBeaconKeySource source = new KeyStoreBeaconKeySource(
            new KeyStoreBeaconKeySource.KeyLocation.Multi(), BEACON_NAMES,
            context(new CountingRetriever(RAW_KEY), new InMemoryCache(), new MutableClock(1000)));

        assertThrows(BeaconException.class, () -> source.getKeyMap(new MaybeKeyId.DontUse()));
        assertInstanceOf(MaybeKeyMap.ShouldHaveKeys.class, source.getKeyMap(new MaybeKeyId.ShouldHave()));
        assertInstanceOf(MaybeKeyMap.Keys.class, source.getKeyMap(new MaybeKeyId.Explicit("tenant1")));
    }

    @Test
    void expiredCacheEntryIsRefetched() {
        CountingRetriever retriever = new CountingRetriever(RAW_KEY);
        MutableClock clock = new MutableClock(1000);
        KeyStoreBeaconKeySource source = new KeyStoreBeaconKeySource(
            new KeyStoreBeaconKeySource.KeyLocation.Single("key1"), BEACON_NAMES,
            context(retriever, new InMemoryCache(), clock));

        source.getKeyMap(new MaybeKeyId.DontUse());
        clock.advanceSeconds(TTL_SECONDS + 1);
        source.getKeyMap(new MaybeKeyId.DontUse());

        assertEquals(2, retriever.calls, "lookup past the TTL must retrieve again");
    }

    @Test
    void cacheIdentifierMatchesTheDafnyByteLayout() {
        InMemoryCache cache = new InMemoryCache();
        KeyStoreBeaconKeySource source = new KeyStoreBeaconKeySource(
            new KeyStoreBeaconKeySource.KeyLocation.Single("key1"), BEACON_NAMES,
            context(new CountingRetriever(RAW_KEY), cache, new MutableClock(1000)));

        source.getKeyMap(new MaybeKeyId.DontUse());

        assertArrayEquals(expectedCacheIdentifier("key1"), cache.lastIdentifier);
    }

    private static KeyStoreBeaconKeySource.Context context(
            BeaconKeyRetriever retriever, BeaconKeyCache cache, Clock clock) {
        return new KeyStoreBeaconKeySource.Context(retriever, cache, TTL_SECONDS, PARTITION, LOGICAL, clock);
    }

    // Independent oracle for the cache identifier: SHA-384 of 0x02 0x00 0x03 0x00 · partition
    // · 0x00 · logicalKeyStoreName · 0x00 · utf8(keyId).
    private static byte[] expectedCacheIdentifier(String keyId) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.writeBytes(new byte[] {0x02, 0x00, 0x03, 0x00});
            out.writeBytes(PARTITION);
            out.write(0x00);
            out.writeBytes(LOGICAL);
            out.write(0x00);
            out.writeBytes(keyId.getBytes(StandardCharsets.UTF_8));
            return MessageDigest.getInstance("SHA-384").digest(out.toByteArray());
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static final class CountingRetriever implements BeaconKeyRetriever {
        private final byte[] key;
        private int calls;

        CountingRetriever(byte[] key) {
            this.key = key;
        }

        @Override public byte[] getBeaconKey(String keyId) {
            calls++;
            return key;
        }
    }

    private static final class InMemoryCache implements BeaconKeyCache {
        private final Map<String, CacheEntry> store = new HashMap<>();
        private byte[] lastIdentifier;

        @Override public Optional<CacheEntry> get(byte[] cacheIdentifier) {
            lastIdentifier = cacheIdentifier;
            return Optional.ofNullable(store.get(HexFormat.of().formatHex(cacheIdentifier)));
        }

        @Override public void put(
                byte[] cacheIdentifier, Map<String, byte[]> hmacKeys, long creationTimeSeconds, long expiryTimeSeconds) {
            store.put(HexFormat.of().formatHex(cacheIdentifier), new CacheEntry(hmacKeys, creationTimeSeconds));
        }
    }

    private static final class MutableClock extends Clock {
        private long epochSeconds;

        MutableClock(long epochSeconds) {
            this.epochSeconds = epochSeconds;
        }

        void advanceSeconds(long seconds) {
            epochSeconds += seconds;
        }

        @Override public Instant instant() {
            return Instant.ofEpochSecond(epochSeconds);
        }

        @Override public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override public Clock withZone(ZoneId zone) {
            return this;
        }
    }
}
