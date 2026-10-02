package software.amazon.cryptography.dbesdk.dynamodbencryption;

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
 * <p>Scope: this slice covers plain (non-virtual) beacons. Virtual fields, compound
 * beacons, {@code partOnly}/shared beacons, and {@code GenerateEncryptedBeacons}
 * orchestration are separate slices (BeaconValueLocation spec §7). The per-beacon HMAC key
 * is an input, derived in {@link BeaconKeyDerivation}.
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

    private StandardBeacon(String name, int lengthBits, TermLoc loc, boolean asSet, int numberOfPartitions) {
        this.name = name;
        this.lengthBits = lengthBits;
        this.loc = loc;
        this.asSet = asSet;
        this.numberOfPartitions = numberOfPartitions;
    }

    /**
     * @param name               the beacon's name (used to derive its HMAC key and in
     *                           error messages)
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
        if (lengthBits < MIN_LENGTH_BITS || lengthBits > MAX_LENGTH_BITS) {
            throw new BeaconException("Beacon length must be between 1 and 63 bits, got " + lengthBits);
        }
        if (numberOfPartitions < 0 || numberOfPartitions > MAX_PARTITION_COUNT) {
            throw new BeaconException(
                "Number of partitions must be between 0 and 255, got " + numberOfPartitions);
        }
        return new StandardBeacon(name, lengthBits, TermLoc.make(loc), asSet, numberOfPartitions);
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
        return asSet ? getHashSet(item, key, partition) : getHashNonSet(item, key, partition);
    }

    // Non-set beacon: the located value's bytes hashed to a single "S" beacon value.
    private Optional<AttributeValue> getHashNonSet(
            Map<String, AttributeValue> item, byte[] key, int partition) {
        return loc.termToBytes(item).map(bytes -> AttributeValue.fromS(hash(bytes, key, partition)));
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
