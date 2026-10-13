package software.amazon.cryptography.dbesdk.dynamodbencryption;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

/**
 * A standard beacon (Beacon behavior spec §2; BeaconValueLocation spec): maps a plaintext
 * value in a DynamoDB item to a truncated keyed hash — the "beacon value" — that can be
 * equality-queried without decrypting. The beacon locates its source value in the item via
 * a {@link TermLoc}, serializes it, and hashes it under a per-beacon HMAC key, keeping the
 * configured number of hash bits.
 *
 * <p>Two levels compose here, matching the Dafny {@code BeaconBase}/{@code StandardBeacon}
 * datatypes in DynamoDbEncryption/dafny/DynamoDbEncryption/src/Beacon.dfy:
 * <ul>
 *   <li>{@link #hash(byte[], byte[], int)} — the {@code basicHash} primitive over
 *       already-serialized bytes: HMAC-SHA384 (first 8 bytes), the partition encoding, and
 *       the bit-truncation to lowercase hex.
 *   <li>{@link #getHash(Map, byte[], int)} — the item-level value production: locate the
 *       value, serialize it, and (for an {@code asSet} beacon) beaconize each set element.
 * </ul>
 *
 * <p>Scope: standard beacons, including the Shared, AsSet, SharedSet, and PartOnly styles
 * (via {@link #keyName()} and {@link #isPartOnly()}). A non-set beacon's location may name a
 * virtual field, resolved through the virtual-field map passed to
 * {@link #getHash(Map, Map, byte[], int)}. The write-path assembly over a set of beacons is
 * {@link BeaconVersion#generateEncryptedBeacons}. The per-beacon HMAC key is an input,
 * derived in {@link BeaconKeyDerivation}.
 */
public final class StandardBeacon {

    private static final String HMAC_ALGORITHM = "HmacSHA384";
    // basicHash keeps the first 8 bytes of the 48-byte HMAC-SHA384 output.
    private static final int HMAC_PREFIX_BYTES = 8;
    private static final int MIN_LENGTH_BITS = 1;
    private static final int MAX_LENGTH_BITS = 63;
    private static final int MAX_PARTITION_COUNT = 255;
    private static final int MAX_PARTITION_NUMBER = 254;

    private final String name;
    private final int lengthBits;
    private final TermLoc loc;
    private final boolean asSet;
    private final int numberOfPartitions;
    // The name of the beacon whose HMAC key this beacon hashes under: its own name, or the
    // `other` beacon's name when this is a shared beacon (Beacon.dfy keyName(), lines 179-182).
    private final String keyName;
    // PartOnly beacons participate in compound beacons but are never written to the item
    // (Beacon spec; GenerateBeacons2 skips them).
    private final boolean partOnly;

    private StandardBeacon(
            String name, int lengthBits, TermLoc loc, boolean asSet, int numberOfPartitions,
            String keyName, boolean partOnly) {
        this.name = name;
        this.lengthBits = lengthBits;
        this.loc = loc;
        this.asSet = asSet;
        this.numberOfPartitions = numberOfPartitions;
        this.keyName = keyName;
        this.partOnly = partOnly;
    }

    /**
     * @param name               the beacon's name (written as {@code aws_dbe_b_<name>} and
     *                           used in error messages)
     * @param lengthBits         beacon length in bits, 1..63 — how many rightmost hash
     *                           bits are kept in the beacon value
     * @param loc                the source-value location string (see {@link TermLoc#make})
     * @param asSet              whether a Set attribute is beaconized element-wise into an
     *                           {@code SS} of beacon values rather than hashed whole
     * @param numberOfPartitions 0..255; 0 leaves the partition unconstrained (the base
     *                           searchable-encryption case, where a partition is encoded
     *                           as-is), 1..255 reduces the partition modulo this count
     */
    public static StandardBeacon create(
            String name, int lengthBits, String loc, boolean asSet, int numberOfPartitions) {
        return create(name, lengthBits, loc, asSet, numberOfPartitions, null, false);
    }

    /**
     * The full factory, carrying the two style flags the write-path orchestration needs
     * (Beacon spec §7, ConfigToInfo.AddStandardBeacons):
     *
     * @param share    the {@code other} beacon's name for a Shared/SharedSet beacon, so
     *                 this beacon hashes under {@code other}'s key and equal values across
     *                 the two collide; {@code null} for an independent beacon
     * @param partOnly whether this beacon is PartOnly — configured for use in compound
     *                 beacons but never written to the item on its own
     */
    public static StandardBeacon create(
            String name, int lengthBits, String loc, boolean asSet, int numberOfPartitions,
            String share, boolean partOnly) {
        if (lengthBits < MIN_LENGTH_BITS || lengthBits > MAX_LENGTH_BITS) {
            throw new BeaconException("Beacon length must be between 1 and 63 bits, got " + lengthBits);
        }
        if (numberOfPartitions < 0 || numberOfPartitions > MAX_PARTITION_COUNT) {
            throw new BeaconException(
                "Number of partitions must be between 0 and 255, got " + numberOfPartitions);
        }
        return new StandardBeacon(
            name, lengthBits, TermLoc.make(loc), asSet, numberOfPartitions,
            share == null ? name : share, partOnly);
    }

    /** The beacon's own name (its written attribute is {@code aws_dbe_b_<name>}). */
    public String name() {
        return name;
    }

    /** The source-value location this beacon reads (used by compound encrypted parts). */
    public TermLoc loc() {
        return loc;
    }

    /**
     * The stored attributes this beacon reads (Beacon {@code GetFields}): the location's
     * root key, or — if that root names a virtual field — that field's underlying roots.
     */
    public List<String> getFields(Map<String, VirtualField> virtualFields) {
        String root = loc.rootKey();
        VirtualField virtualField = virtualFields.get(root);
        return virtualField != null ? virtualField.getFields() : List.of(root);
    }

    /**
     * The name of the beacon whose HMAC key this beacon hashes under — its own name, or the
     * {@code other} beacon's name when shared (Beacon.dfy keyName()). The orchestration
     * looks this up in the derived HMAC-key map.
     */
    public String keyName() {
        return keyName;
    }

    /** Whether this beacon is PartOnly and so must not be written to the item. */
    public boolean isPartOnly() {
        return partOnly;
    }

    /**
     * The beacon value for an item (Beacon spec §5–§6): locate this beacon's source value,
     * serialize and hash it, or beaconize its elements for an {@code asSet} beacon. Empty
     * when the source field is absent — no beacon is written for that item.
     *
     * @param item      the DynamoDB item being written or queried
     * @param key       the per-beacon HMAC key ({@link BeaconKeyDerivation})
     * @param partition the write/query partition number, 0..254
     * @throws BeaconException if an {@code asSet} beacon's located value is not a Set
     */
    public Optional<AttributeValue> getHash(Map<String, AttributeValue> item, byte[] key, int partition) {
        return getHash(item, Map.of(), key, partition);
    }

    /**
     * The beacon value for an item, resolving a location that names a virtual field through
     * {@code virtualFields} (Beacon.dfy {@code getHash} over {@code VirtToBytes}). Set
     * beacons never read a virtual field — a virtual field is always a string, not a set —
     * so {@code virtualFields} is consulted only on the non-set path.
     *
     * @param virtualFields the version's virtual fields, by name (may be empty)
     */
    public Optional<AttributeValue> getHash(
            Map<String, AttributeValue> item, Map<String, VirtualField> virtualFields, byte[] key, int partition) {
        return asSet ? getHashSet(item, key, partition) : getHashNonSet(item, virtualFields, key, partition);
    }

    // Non-set beacon: the located value's bytes hashed to a single "S" beacon value.
    private Optional<AttributeValue> getHashNonSet(
            Map<String, AttributeValue> item, Map<String, VirtualField> virtualFields, byte[] key, int partition) {
        return virtToBytes(item, virtualFields).map(bytes -> AttributeValue.fromS(hash(bytes, key, partition)));
    }

    // The source bytes to hash (Virtual.dfy VirtToBytes): a location that names a virtual
    // field hashes the UTF-8 bytes of the field's string value; any other location hashes
    // the located attribute's serialized bytes.
    private Optional<byte[]> virtToBytes(Map<String, AttributeValue> item, Map<String, VirtualField> virtualFields) {
        Optional<String> rootKey = loc.singleSegmentKey();
        if (rootKey.isPresent() && virtualFields.containsKey(rootKey.get())) {
            return virtualFields.get(rootKey.get()).getValue(item).map(s -> s.getBytes(StandardCharsets.UTF_8));
        }
        return loc.termToBytes(item);
    }

    /**
     * The beacon's plaintext (unhashed) value for an item (Virtual.dfy {@code VirtToAttr}):
     * the virtual field's string when the location names one, otherwise the located
     * attribute. This is the value a fully-signed beacon contributes before encryption.
     */
    Optional<AttributeValue> getNaked(Map<String, AttributeValue> item, Map<String, VirtualField> virtualFields) {
        Optional<String> rootKey = loc.singleSegmentKey();
        if (rootKey.isPresent() && virtualFields.containsKey(rootKey.get())) {
            return virtualFields.get(rootKey.get()).getValue(item).map(AttributeValue::fromS);
        }
        return loc.termToAttr(item);
    }

    /**
     * The beacon value for a query value (Beacon.dfy {@code GetBeaconValue}): hash the
     * supplied value the same way the write path hashes the stored value, so an equality
     * query matches the written beacon. The value is given directly (not located in an
     * item), so it is serialized with {@link DynamoToStruct} exactly as
     * {@link TermLoc#termToBytes} serializes a located value.
     *
     * <p>A Set-valued query beaconizes each element: an {@code asSet} beacon queried with a
     * non-scalar value, or any beacon queried under {@code contains} with a Set value
     * ({@code forContains}), yields the {@code SS} of element beacons; a scalar value yields
     * a single beacon (e.g. {@code contains(setAttr, :element)}).
     *
     * @param key         the per-beacon HMAC key ({@link BeaconKeyDerivation})
     * @param forContains whether the surrounding operation is {@code contains}
     * @throws BeaconException if an {@code asSet} query value is not a Set type
     */
    public AttributeValue getBeaconValue(AttributeValue value, byte[] key, boolean forContains, int partition) {
        boolean nonScalar = value.type() != AttributeValue.Type.S
            && value.type() != AttributeValue.Type.N
            && value.type() != AttributeValue.Type.B;
        boolean setValue = value.type() == AttributeValue.Type.SS
            || value.type() == AttributeValue.Type.NS
            || value.type() == AttributeValue.Type.BS;
        if (asSet && nonScalar) {
            return valueToSet(value, key, partition);
        }
        if (forContains && setValue) {
            return valueToSet(value, key, partition);
        }
        return AttributeValue.fromS(hash(DynamoToStruct.attrToStructured(value).value(), key, partition));
    }

    // Set beacon: the located Set value turned into an "SS" of per-element beacon values.
    private Optional<AttributeValue> getHashSet(
            Map<String, AttributeValue> item, byte[] key, int partition) {
        return loc.termToAttr(item).map(value -> valueToSet(value, key, partition));
    }

    // Beaconize each element of a Set attribute (Beacon spec §6). An asSet beacon over a
    // non-Set value is a configuration error. The result is always an "SS", even for a
    // number or binary source set.
    private AttributeValue valueToSet(AttributeValue value, byte[] key, int partition) {
        List<AttributeValue> elements = switch (value.type()) {
            case SS -> value.ss().stream().map(AttributeValue::fromS).toList();
            case NS -> value.ns().stream().map(AttributeValue::fromN).toList();
            case BS -> value.bs().stream().map(AttributeValue::fromB).toList();
            default -> throw new BeaconException(
                "Beacon " + name + " has style AsSet, but attribute has type " + value.type() + ".");
        };
        return AttributeValue.fromSs(beaconizeSet(elements, key, partition));
    }

    // Hash each element in input order, keeping only the first occurrence of each distinct
    // beacon value (dedup is on the output, not the input — Beacon spec §6).
    private List<String> beaconizeSet(List<AttributeValue> elements, byte[] key, int partition) {
        List<String> beaconValues = new ArrayList<>();
        for (AttributeValue element : elements) {
            String beaconValue = hash(DynamoToStruct.attrToStructured(element).value(), key, partition);
            if (!beaconValues.contains(beaconValue)) {
                beaconValues.add(beaconValue);
            }
        }
        return beaconValues;
    }

    /**
     * The beacon value for an already-serialized plaintext value: the {@code basicHash}
     * of {@code value}, augmented by this beacon's partition encoding, under {@code key}.
     *
     * @param value     the attribute's serialized bytes (DynamoToStruct top-level bytes)
     * @param key       the per-beacon HMAC key (Beacon spec §6)
     * @param partition the write/query partition number, 0..254 (0 is the base case)
     * @return the lowercase-hex beacon value, exactly {@code ceil(lengthBits / 4)} chars
     */
    public String hash(byte[] value, byte[] key, int partition) {
        if (partition < 0 || partition > MAX_PARTITION_NUMBER) {
            throw new BeaconException("Partition number must be between 0 and 254, got " + partition);
        }
        return basicHash(value, key, lengthBits, constrainedPartition(partition));
    }

    // The partition bytes appended to the value before hashing (Beacon spec §4). An
    // unconstrained beacon (numberOfPartitions == 0) or partition 0 encodes the partition
    // as-is; otherwise the partition is reduced modulo the partition count.
    byte[] constrainedPartition(int partition) {
        if (numberOfPartitions == 0 || partition == 0) {
            return partitionNumberToBytes(partition);
        }
        return partitionNumberToBytes(partition % numberOfPartitions);
    }

    // Partition 0 appends nothing; partition N in 1..254 appends the single byte [N].
    static byte[] partitionNumberToBytes(int partition) {
        return partition == 0 ? new byte[0] : new byte[] {(byte) partition};
    }

    // basicHash (Beacon spec §2): HMAC-SHA384(key, value ++ partitionBytes), first 8
    // bytes, reduced to the rightmost `lengthBits` bits as lowercase hex (§3).
    static String basicHash(byte[] value, byte[] key, int lengthBits, byte[] partitionBytes) {
        byte[] message = new byte[value.length + partitionBytes.length];
        System.arraycopy(value, 0, message, 0, value.length);
        System.arraycopy(partitionBytes, 0, message, value.length, partitionBytes.length);
        return bytesToHex(getHmac(message, key), lengthBits);
    }

    // HMAC-SHA384 of data under key, keeping the first 8 bytes.
    static byte[] getHmac(byte[] data, byte[] key) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return Arrays.copyOf(mac.doFinal(data), HMAC_PREFIX_BYTES);
        } catch (GeneralSecurityException e) {
            throw new BeaconException("Failed to compute beacon HMAC: " + e.getMessage());
        }
    }

    // Render the rightmost `lengthBits` bits of an 8-byte MAC as lowercase hex (Beacon
    // spec §3): the rightmost ceil(lengthBits/8) bytes are used, the output is
    // ceil(lengthBits/4) chars, and the leading nibble is truncated to `lengthBits mod 4`
    // bits (or 4 when that is 0).
    static String bytesToHex(byte[] mac, int lengthBits) {
        int numBytes = (lengthBits + 7) / 8;
        int numChars = (lengthBits + 3) / 4;
        int topBits = lengthBits % 4 == 0 ? 4 : lengthBits % 4;

        int start = mac.length - numBytes;
        int first = mac[start] & 0xFF;
        StringBuilder hex = new StringBuilder(numChars);
        if (numChars == 2 * numBytes) {
            // Even char count: the full leading byte is rendered, its top nibble truncated.
            hex.append(hexChar(truncateNibble(first >> 4, topBits)));
            hex.append(hexChar(first & 0x0F));
        } else {
            // Odd char count: the leading byte's high nibble is dropped; its low nibble is
            // the (truncated) top hex char.
            hex.append(hexChar(truncateNibble(first & 0x0F, topBits)));
        }
        for (int i = start + 1; i < mac.length; i++) {
            int b = mac[i] & 0xFF;
            hex.append(hexChar(b >> 4));
            hex.append(hexChar(b & 0x0F));
        }
        return hex.toString();
    }

    // Keep only the low `bits` (1..4) bits of a nibble.
    private static int truncateNibble(int nibble, int bits) {
        return nibble & ((1 << bits) - 1);
    }

    private static char hexChar(int value) {
        return (char) (value < 10 ? '0' + value : 'a' + (value - 10));
    }
}
