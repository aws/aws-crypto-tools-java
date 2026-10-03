package software.amazon.cryptography.dbesdk.dynamodbencryption;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import software.amazon.cryptography.dbesdk.structuredencryption.crypto.Hkdf;

/**
 * Derives the per-beacon HMAC keys that the {@link StandardBeacon} primitive consumes
 * (BeaconKeyMaterials behavior spec §2). From a single beacon key (retrieved elsewhere
 * from the key store), each standard beacon gets its own key via HKDF-SHA512.
 *
 * <p>Scope: the pure HKDF-SHA512 derivation only. Retrieving the beacon key from the key
 * store / branch-key materials is the MPL boundary and belongs at the searchable-encryption
 * seam (spec §7). Behavioral parity target: {@code GetBeaconKey} / {@code GetAllKeys} in
 * DynamoDbEncryption/dafny/DynamoDbEncryption/src/SearchInfo.dfy.
 *
 * <p>Note the pipeline uses two distinct hashes: this derivation is HKDF-<b>SHA512</b>,
 * while the {@code basicHash} that uses the derived key is HMAC-<b>SHA384</b>.
 */
public final class BeaconKeyDerivation {

    // info = UTF8("AWS_DBE_SCAN_BEACON" + beaconName), per the HMAC-key-generation spec.
    private static final String BEACON_INFO_PREFIX = "AWS_DBE_SCAN_BEACON";
    private static final String HMAC_SHA512 = "HmacSHA512";
    private static final int BEACON_KEY_LENGTH = 64;

    private BeaconKeyDerivation() {}

    /**
     * The HMAC key for one beacon: {@code HKDF-SHA512(salt=None, ikm=beaconKey,
     * info=UTF8("AWS_DBE_SCAN_BEACON" + beaconName), length=64)}.
     *
     * @param beaconKey  the beacon key (branch-key material) to derive from
     * @param beaconName the beacon's own name (not the {@code aws_dbe_b_} attribute name)
     * @return the 64-byte derived HMAC key
     */
    public static byte[] deriveBeaconKey(byte[] beaconKey, String beaconName) {
        byte[] info = (BEACON_INFO_PREFIX + beaconName).getBytes(StandardCharsets.UTF_8);
        // salt=None means a HashLen (64) zero-byte salt per RFC 5869 §2.2 — Hkdf handles null.
        return Hkdf.deriveKey(HMAC_SHA512, null, beaconKey, info, BEACON_KEY_LENGTH);
    }

    /**
     * The HMAC key map for a set of beacons: beacon name → {@link #deriveBeaconKey}
     * (BeaconKeyMaterials spec §3). Beacon names must be unique (enforced here; upstream
     * they come from a deduplicated set).
     */
    public static Map<String, byte[]> deriveHmacKeys(byte[] beaconKey, List<String> beaconNames) {
        Map<String, byte[]> keys = new LinkedHashMap<>();
        for (String name : beaconNames) {
            if (keys.containsKey(name)) {
                throw new BeaconException("Duplicate beacon name: " + name);
            }
            keys.put(name, deriveBeaconKey(beaconKey, name));
        }
        return keys;
    }
}
