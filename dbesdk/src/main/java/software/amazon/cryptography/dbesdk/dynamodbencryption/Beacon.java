package software.amazon.cryptography.dbesdk.dynamodbencryption;

import java.util.Map;
import java.util.Optional;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

/**
 * A beacon as the write path sees it, unifying standard and compound beacons so a
 * {@link BeaconVersion} can hold and iterate them together (SearchInfo.dfy
 * {@code datatype Beacon = Standard | Compound}). Each beacon reports whether it is
 * encrypted — which decides which write pass emits it and under what attribute name — and
 * computes its value for an item.
 */
public sealed interface Beacon permits Beacon.Standard, Beacon.Compound {

    /** The beacon's configured name. */
    String name();

    /** The attribute name the beacon value is stored under. */
    String beaconName();

    /**
     * Whether this beacon is written to the encrypted output ({@code true}) or signed into
     * the item before encryption ({@code false}). Standard beacons are always encrypted;
     * a compound beacon is encrypted iff it has an encrypted part.
     */
    boolean isEncrypted();

    /** Whether this beacon is PartOnly and so must never be written to the item on its own. */
    boolean isPartOnly();

    /**
     * The beacon value for an item, or empty when the source field is absent (standard) or
     * no constructor is satisfied (compound).
     *
     * @param hmacKeys per-beacon HMAC keys, or {@code null} for the keyless plaintext value
     *                 (the form signed into the item before encryption)
     */
    Optional<AttributeValue> attrHash(
        Map<String, AttributeValue> item, Map<String, VirtualField> virtualFields,
        Map<String, byte[]> hmacKeys, int partition);

    /**
     * The beacon value for a query value (SearchInfo.dfy {@code Beacon.GetBeaconValue}): the
     * form a compared value in a query is rewritten to so DynamoDB matches on the stored
     * beacon. Under {@link MaybeKeyMap.DontUseKeys} the value is returned unchanged (the
     * output-filter path compares plaintext); otherwise it is beaconized under the resolved
     * keys.
     *
     * @param forEquality whether the operation is equality ({@code =}, {@code <>}, {@code IN})
     * @param forContains whether the operation is {@code contains}
     * @throws BeaconException if a required key is missing or a key id was required but absent
     */
    AttributeValue getBeaconValue(
        AttributeValue value, MaybeKeyMap keys, boolean forEquality, boolean forContains, int partition);

    /** A standard beacon; always encrypted, written as {@code aws_dbe_b_<name>}. */
    record Standard(StandardBeacon beacon) implements Beacon {
        @Override public String name() {
            return beacon.name();
        }

        @Override public String beaconName() {
            return BeaconVersion.BEACON_PREFIX + beacon.name();
        }

        @Override public boolean isEncrypted() {
            return true;
        }

        @Override public boolean isPartOnly() {
            return beacon.isPartOnly();
        }

        @Override public Optional<AttributeValue> attrHash(
                Map<String, AttributeValue> item, Map<String, VirtualField> virtualFields,
                Map<String, byte[]> hmacKeys, int partition) {
            if (hmacKeys == null) {
                return beacon.getNaked(item, virtualFields);
            }
            byte[] key = hmacKeys.get(beacon.keyName());
            if (key == null) {
                throw new BeaconException("Internal error, no key for " + beacon.keyName());
            }
            return beacon.getHash(item, virtualFields, key, partition);
        }

        @Override public AttributeValue getBeaconValue(
                AttributeValue value, MaybeKeyMap keys, boolean forEquality, boolean forContains, int partition) {
            if (keys instanceof MaybeKeyMap.DontUseKeys) {
                return value;
            }
            if (keys instanceof MaybeKeyMap.ShouldHaveKeys) {
                throw new BeaconException(
                    "Need KeyId because of beacon " + beacon.keyName() + " but no KeyId found in query");
            }
            byte[] key = ((MaybeKeyMap.Keys) keys).keys().get(beacon.keyName());
            if (key == null) {
                throw new BeaconException("Internal error. Beacon " + beacon.keyName() + " has no key.");
            }
            return beacon.getBeaconValue(value, key, forContains, partition);
        }
    }

    /**
     * A compound beacon; encrypted iff it has an encrypted part. An encrypted compound
     * beacon is written as {@code aws_dbe_b_<name>}, a fully-signed one as {@code <name>}
     * (ConfigToInfo CreateCompoundBeacon).
     */
    record Compound(CompoundBeacon beacon) implements Beacon {
        @Override public String name() {
            return beacon.name();
        }

        @Override public String beaconName() {
            return beacon.isEncrypted() ? BeaconVersion.BEACON_PREFIX + beacon.name() : beacon.name();
        }

        @Override public boolean isEncrypted() {
            return beacon.isEncrypted();
        }

        @Override public boolean isPartOnly() {
            return false;
        }

        @Override public Optional<AttributeValue> attrHash(
                Map<String, AttributeValue> item, Map<String, VirtualField> virtualFields,
                Map<String, byte[]> hmacKeys, int partition) {
            return beacon.getValue(item, virtualFields, hmacKeys, partition).map(AttributeValue::fromS);
        }

        @Override public AttributeValue getBeaconValue(
                AttributeValue value, MaybeKeyMap keys, boolean forEquality, boolean forContains, int partition) {
            if (keys instanceof MaybeKeyMap.DontUseKeys) {
                return value;
            }
            if (keys instanceof MaybeKeyMap.ShouldHaveKeys) {
                throw new BeaconException(
                    "Multi-tenant compound beacon queries are not yet supported on the native read path.");
            }
            return beacon.getBeaconValue(
                value, ((MaybeKeyMap.Keys) keys).keys(), forEquality, partition);
        }
    }
}
