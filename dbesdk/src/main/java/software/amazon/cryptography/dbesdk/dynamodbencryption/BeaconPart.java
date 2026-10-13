package software.amazon.cryptography.dbesdk.dynamodbencryption;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

/**
 * One part of a compound beacon (CompoundBeacon.dfy {@code BeaconPart}). A part has a
 * non-empty prefix and a source location, and contributes {@code prefix + partValue} to
 * the assembled compound value:
 * <ul>
 *   <li>a {@link Signed} part contributes {@code prefix + plaintext};
 *   <li>an {@link Encrypted} part contributes {@code prefix + beaconHash(plaintext)}
 *       (the standard-beacon hash of the UTF-8 value under the part's key).
 * </ul>
 * A part's location may name a virtual field, so {@link #getString} is virtual-field aware.
 */
public sealed interface BeaconPart permits BeaconPart.Encrypted, BeaconPart.Signed {

    String prefix();

    String name();

    /** The part's located source string (virtual-field aware), or empty if absent. */
    Optional<String> getString(Map<String, AttributeValue> item, Map<String, VirtualField> virtualFields);

    /**
     * The stored attributes this part reads (CompoundBeacon.dfy {@code BeaconPart.GetFields}):
     * the location's root key, or that root's virtual-field roots when it names one.
     */
    List<String> getFields(Map<String, VirtualField> virtualFields);

    /**
     * The keyed part value: {@code prefix + plaintext} for a signed part,
     * {@code prefix + hash} for an encrypted part. The keyless "naked" value is just
     * {@code prefix + plaintext} for every part and is handled by the caller.
     */
    String partValue(String data, Map<String, byte[]> hmacKeys, int partition);

    // Resolve a location to its string value, treating a single-segment location that
    // names a virtual field as that field.
    private static Optional<String> locToString(
            TermLoc loc, Map<String, AttributeValue> item, Map<String, VirtualField> virtualFields) {
        Optional<String> key = loc.singleSegmentKey();
        if (key.isPresent() && virtualFields.containsKey(key.get())) {
            return virtualFields.get(key.get()).getValue(item);
        }
        return loc.termToString(item);
    }

    /** An encrypted part: its value is hashed under the embedded standard beacon's key. */
    record Encrypted(String prefix, StandardBeacon beacon) implements BeaconPart {
        @Override public String name() {
            return beacon.name();
        }

        @Override public Optional<String> getString(
                Map<String, AttributeValue> item, Map<String, VirtualField> virtualFields) {
            return locToString(beacon.loc(), item, virtualFields);
        }

        @Override public List<String> getFields(Map<String, VirtualField> virtualFields) {
            return beacon.getFields(virtualFields);
        }

        @Override public String partValue(String data, Map<String, byte[]> hmacKeys, int partition) {
            byte[] key = hmacKeys.get(beacon.keyName());
            if (key == null) {
                throw new BeaconException("Internal error, no key for " + beacon.keyName());
            }
            return prefix + beacon.hash(data.getBytes(StandardCharsets.UTF_8), key, partition);
        }
    }

    /** A signed part: its value is the plaintext (no key needed). */
    record Signed(String prefix, String name, TermLoc loc) implements BeaconPart {
        @Override public Optional<String> getString(
                Map<String, AttributeValue> item, Map<String, VirtualField> virtualFields) {
            return locToString(loc, item, virtualFields);
        }

        @Override public List<String> getFields(Map<String, VirtualField> virtualFields) {
            String root = loc.rootKey();
            VirtualField virtualField = virtualFields.get(root);
            return virtualField != null ? virtualField.getFields() : List.of(root);
        }

        @Override public String partValue(String data, Map<String, byte[]> hmacKeys, int partition) {
            return prefix + data;
        }
    }
}
