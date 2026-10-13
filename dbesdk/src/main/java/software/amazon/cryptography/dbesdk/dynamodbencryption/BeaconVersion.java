package software.amazon.cryptography.dbesdk.dynamodbencryption;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

/**
 * A beacon version's write-path assembly (SearchInfo.dfy {@code BeaconVersion}): given an
 * item and the derived per-beacon HMAC keys, produce the beacon attributes to add to the
 * item. The version holds its beacons (standard and compound) and virtual fields together,
 * and emits them in two passes mirroring the Dafny source:
 * <ul>
 *   <li>{@link #generateSignedBeacons} — the fully-signed compound beacons, computed from
 *       plaintext part values and signed into the item <em>before</em> encryption, each as
 *       attribute {@code <name>} ({@code GenerateSignedBeacons}).
 *   <li>{@link #generateEncryptedBeacons} — the standard beacons and the compound beacons
 *       with an encrypted part, written <em>after</em> encryption, each as
 *       {@code aws_dbe_b_<name>} ({@code GenerateEncryptedBeacons}).
 * </ul>
 *
 * <p>The HMAC-key map is an input (derived by {@link BeaconKeyDerivation} from the beacon
 * key the MPL key store returns); retrieving that key and merging these attributes into the
 * item is the {@link software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms.SearchInfo}
 * seam, not this class.
 */
public final class BeaconVersion {

    /** The attribute-name prefix every encrypted beacon is written under. */
    public static final String BEACON_PREFIX = "aws_dbe_b_";

    private final List<Beacon> beacons;
    private final Map<String, Beacon> beaconsByName;
    private final Map<String, VirtualField> virtualFields;
    private final List<String> standardBeaconNames;
    // The ENCRYPT_AND_SIGN fields that are not themselves beacons. Querying one of these is
    // an error (it is encrypted and so cannot be matched without a beacon), which the query
    // rewrite reports via HasBeacon/GetBeacon2.
    private final Set<String> encryptedFields;

    private BeaconVersion(
            List<Beacon> beacons, Map<String, Beacon> beaconsByName, Map<String, VirtualField> virtualFields,
            List<String> standardBeaconNames, Set<String> encryptedFields) {
        this.beacons = beacons;
        this.beaconsByName = beaconsByName;
        this.virtualFields = virtualFields;
        this.standardBeaconNames = standardBeaconNames;
        this.encryptedFields = encryptedFields;
    }

    /**
     * Build a beacon version from standard beacons only — no compound beacons or virtual
     * fields. Convenience for the standard-beacon write path.
     *
     * @throws BeaconException if two beacons share a name
     */
    public static BeaconVersion of(List<StandardBeacon> standardBeacons) {
        List<Beacon> wrapped = new ArrayList<>(standardBeacons.size());
        for (StandardBeacon beacon : standardBeacons) {
            wrapped.add(new Beacon.Standard(beacon));
        }
        return create(wrapped, Map.of());
    }

    /**
     * Build a beacon version from its full set of beacons (standard and compound) and the
     * virtual fields they may read.
     *
     * @throws BeaconException if two beacons share a name (ConfigToInfo: "Duplicate ... name")
     */
    public static BeaconVersion create(List<Beacon> beacons, Map<String, VirtualField> virtualFields) {
        return create(beacons, virtualFields, Set.of());
    }

    /**
     * Build a beacon version with its beacons, virtual fields, and the encrypted
     * (ENCRYPT_AND_SIGN) field names that are not themselves beacons — the latter so the
     * query rewrite can reject a query that references an encrypted field with no beacon.
     *
     * @throws BeaconException if two beacons share a name (ConfigToInfo: "Duplicate ... name")
     */
    public static BeaconVersion create(
            List<Beacon> beacons, Map<String, VirtualField> virtualFields, Set<String> encryptedFields) {
        List<String> standardNames = new ArrayList<>();
        Map<String, Beacon> byName = new LinkedHashMap<>();
        for (Beacon beacon : beacons) {
            if (byName.containsKey(beacon.name())) {
                throw new BeaconException("Duplicate beacon name : " + beacon.name());
            }
            byName.put(beacon.name(), beacon);
            if (beacon instanceof Beacon.Standard) {
                standardNames.add(beacon.name());
            }
        }
        return new BeaconVersion(
            List.copyOf(beacons), Map.copyOf(byName), Map.copyOf(virtualFields),
            List.copyOf(standardNames), Set.copyOf(encryptedFields));
    }

    /** Whether {@code field} names a configured beacon (SearchInfo.dfy {@code IsBeacon}). */
    public boolean isBeacon(String field) {
        return beaconsByName.containsKey(field);
    }

    /** The beacon configured under {@code field}, or {@code null} if none. */
    public Beacon getBeacon(String field) {
        return beaconsByName.get(field);
    }

    /** The ENCRYPT_AND_SIGN field names that are not themselves beacons. */
    public Set<String> encryptedFields() {
        return encryptedFields;
    }

    /**
     * The standard-beacon names whose HMAC keys must be derived for this version. A compound
     * beacon's encrypted part reuses the key of the standard beacon it references, which is
     * itself a configured standard beacon, so this list covers every key needed.
     */
    public List<String> beaconNames() {
        return standardBeaconNames;
    }

    /**
     * The names of the signed (non-encrypted) beacons — the fully-signed compound beacons,
     * which {@code addSignedBeacons} writes before encryption as attribute {@code <name>}
     * (SearchInfo.dfy {@code ListSignedBeacons}). Each must be configured SIGN_ONLY on the
     * item encryptor so {@code EncryptItem} authenticates it (transforms Index.dfy
     * {@code AddSignedBeaconActions}).
     */
    public List<String> listSignedBeacons() {
        List<String> names = new ArrayList<>();
        for (Beacon beacon : beacons) {
            if (!beacon.isEncrypted()) {
                names.add(beacon.name());
            }
        }
        return names;
    }

    /**
     * The signed beacons for an item, each as attribute {@code <name>}: the fully-signed
     * compound beacons, from plaintext part values. Signed into the item before encryption.
     */
    public Map<String, AttributeValue> generateSignedBeacons(Map<String, AttributeValue> item, int partition) {
        return generate(item, null, Kind.SIGNED, partition);
    }

    /**
     * The encrypted beacons for an item, each as {@code aws_dbe_b_<name>}: the standard
     * beacons and the compound beacons with an encrypted part. Added after encryption.
     *
     * @param hmacKeys beacon name -&gt; per-beacon HMAC key ({@link BeaconKeyDerivation})
     * @throws BeaconException if a required HMAC key is missing from {@code hmacKeys}
     */
    public Map<String, AttributeValue> generateEncryptedBeacons(
            Map<String, AttributeValue> item, Map<String, byte[]> hmacKeys, int partition) {
        return generate(item, hmacKeys, Kind.ENCRYPTED, partition);
    }

    /**
     * The "plain" beacons for an item — every beacon, signed and encrypted alike, computed
     * keyless and stored under its {@code beaconName()} (SearchInfo.dfy
     * {@code GeneratePlainBeacons} = {@code GenerateBeacons2(.., DontUseKeys, AnyBeacon, ..)}).
     *
     * <p>These are not written to the item; the read-path output filter recomputes them from
     * each decrypted item and evaluates the beaconized query against {@code item + these}.
     * Keyless here means plaintext (not hashed): the query's compared values are left
     * plaintext under {@code DontUseKeys} too, so the re-filter reproduces the original
     * plaintext comparison and removes the beacon query's false positives.
     */
    public Map<String, AttributeValue> generatePlainBeacons(Map<String, AttributeValue> item, int partition) {
        return generate(item, null, Kind.ANY, partition);
    }

    // Which beacons a generation pass emits (Dafny BeaconType / IsBeaconOfType).
    private enum Kind { SIGNED, ENCRYPTED, ANY }

    // GenerateBeacons2: for every beacon of the requested kind that is not PartOnly and
    // whose value is present, add beaconName -> value. A null key map yields the keyless
    // (plaintext) value; a key map yields the keyed value.
    private Map<String, AttributeValue> generate(
            Map<String, AttributeValue> item, Map<String, byte[]> hmacKeys, Kind kind, int partition) {
        Map<String, AttributeValue> result = new LinkedHashMap<>();
        for (Beacon beacon : beacons) {
            if (!kindMatches(kind, beacon) || beacon.isPartOnly()) {
                continue;
            }
            beacon.attrHash(item, virtualFields, hmacKeys, partition)
                .ifPresent(value -> result.put(beacon.beaconName(), value));
        }
        return result;
    }

    private static boolean kindMatches(Kind kind, Beacon beacon) {
        return switch (kind) {
            case SIGNED -> !beacon.isEncrypted();
            case ENCRYPTED -> beacon.isEncrypted();
            case ANY -> true;
        };
    }
}
