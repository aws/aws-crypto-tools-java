package software.amazon.cryptography.dbesdk.dynamodbencryption;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Terminal;

/**
 * DynamoDB attribute serialization (DynamoToStruct behavior spec): converts a
 * DynamoDB {@link AttributeValue} to/from a StructuredEncryption {@link Terminal}
 * (value bytes + a 2-byte type id).
 *
 * <p>Top-level values carry no length/type prefix (the type id travels on the
 * terminal); every nested element inside a set, list, or map is prefixed with
 * its 2-byte type id and a big-endian 4-byte length. Sets and maps are
 * canonicalized on encode: string/number set entries and map keys are ordered by
 * UTF-16 binary order, binary set entries by their raw bytes; lists keep their
 * order. Numbers are DynamoDB-normalized (see {@link NumberNormalizer}).
 */
public final class DynamoToStruct {

    static final byte[] STRING = {0x00, 0x01};
    static final byte[] NUMBER = {0x00, 0x02};
    static final byte[] BINARY = {(byte) 0xFF, (byte) 0xFF};
    static final byte[] BOOLEAN = {0x00, 0x04};
    static final byte[] NULL = {0x00, 0x00};
    static final byte[] STRING_SET = {0x01, 0x01};
    static final byte[] NUMBER_SET = {0x01, 0x02};
    static final byte[] BINARY_SET = {0x01, (byte) 0xFF};
    static final byte[] MAP = {0x02, 0x00};
    static final byte[] LIST = {0x03, 0x00};

    private static final int MAX_STRUCTURE_DEPTH = 32;
    private static final int TYPEID_LEN = 2;
    private static final int LENGTH_LEN = 4;
    private static final int MAX_ATTR_NAME_LEN = 65535;

    // Attribute names beginning with this prefix (e.g. aws_dbe_head, aws_dbe_foot)
    // are reserved by the encryption client and never configured as signed/encrypted.
    private static final String RESERVED_PREFIX = "aws_dbe_";

    private DynamoToStruct() {}

    /** Serialize a DynamoDB attribute to a terminal (top-level: no length/type prefix). */
    public static Terminal attrToStructured(AttributeValue attr) {
        return new Terminal(attrToBytes(attr, false, 1), attrToTypeId(attr));
    }

    /** Deserialize a terminal back to a DynamoDB attribute. Rejects trailing bytes. */
    public static AttributeValue structuredToAttr(Terminal terminal) {
        if (terminal.typeId().length != TYPEID_LEN) {
            throw new DynamoToStructException("Type ID must be two bytes");
        }
        byte[] value = terminal.value();
        Decoded decoded = decodeValue(value, 0, terminal.typeId(), value.length, 1);
        if (decoded.consumed() != value.length) {
            throw new DynamoToStructException("Mismatch between length of encoded data and length of data");
        }
        return decoded.value();
    }

    /**
     * Convert a DynamoDB item to a terminal map for the structured-encryption
     * pipeline (DynamoToStruct behavior spec §6). {@code DO_NOTHING} attributes are
     * omitted — they are neither signed nor encrypted — unless they carry the
     * reserved prefix. Every other attribute (including those absent from
     * {@code actions}) becomes a terminal.
     */
    public static Map<String, Terminal> itemToStructured(
            Map<String, AttributeValue> item, Map<String, CryptoAction> actions) {
        Map<String, Terminal> structured = new LinkedHashMap<>();
        for (Map.Entry<String, AttributeValue> entry : item.entrySet()) {
            String name = entry.getKey();
            if (actions.get(name) == CryptoAction.DO_NOTHING && !name.startsWith(RESERVED_PREFIX)) {
                continue;
            }
            structured.put(name, attrToStructured(entry.getValue()));
        }
        return structured;
    }

    /**
     * Rebuild the DynamoDB item to store from an encrypted structured map
     * (DynamoToStruct behavior spec §6). Each {@code ENCRYPT_AND_SIGN} attribute is
     * replaced by the encrypted terminal serialized back to an attribute; other
     * original attributes pass through unchanged; the reserved attributes the
     * structured-encryption client added (header/footer, present in {@code s} but
     * not in {@code orig}) are serialized in.
     */
    public static Map<String, AttributeValue> structuredToItemEncrypt(
            Map<String, Terminal> s,
            Map<String, AttributeValue> orig,
            Map<String, CryptoAction> actions) {
        Map<String, AttributeValue> item = convertOriginalAttributes(s, orig, actions);
        for (Map.Entry<String, Terminal> entry : s.entrySet()) {
            if (!orig.containsKey(entry.getKey())) {
                item.put(entry.getKey(), structuredToAttr(entry.getValue()));
            }
        }
        return item;
    }

    /**
     * Rebuild the plaintext DynamoDB item from a decrypted structured map
     * (DynamoToStruct behavior spec §6). Each {@code ENCRYPT_AND_SIGN} attribute is
     * replaced by its decrypted value; other original attributes pass through; the
     * reserved header/footer attributes are dropped (they are reserved-prefix in
     * {@code orig}, and any structured entry absent from {@code orig} is ignored).
     */
    public static Map<String, AttributeValue> structuredToItemDecrypt(
            Map<String, Terminal> s,
            Map<String, AttributeValue> orig,
            Map<String, CryptoAction> actions) {
        return convertOriginalAttributes(s, orig, actions);
    }

    // For each non-reserved original attribute: the decrypted/re-serialized terminal
    // when it is ENCRYPT_AND_SIGN and present in the structured map, else the original
    // value. Shared by both structuredToItem directions.
    private static Map<String, AttributeValue> convertOriginalAttributes(
            Map<String, Terminal> s,
            Map<String, AttributeValue> orig,
            Map<String, CryptoAction> actions) {
        Map<String, AttributeValue> item = new LinkedHashMap<>();
        for (Map.Entry<String, AttributeValue> entry : orig.entrySet()) {
            String name = entry.getKey();
            if (name.startsWith(RESERVED_PREFIX)) {
                continue;
            }
            if (s.containsKey(name) && actions.get(name) == CryptoAction.ENCRYPT_AND_SIGN) {
                item.put(name, structuredToAttr(s.get(name)));
            } else {
                item.put(name, entry.getValue());
            }
        }
        return item;
    }

    static byte[] attrToTypeId(AttributeValue attr) {
        return switch (attr.type()) {
            case S -> STRING;
            case N -> NUMBER;
            case B -> BINARY;
            case SS -> STRING_SET;
            case NS -> NUMBER_SET;
            case BS -> BINARY_SET;
            case M -> MAP;
            case L -> LIST;
            case NUL -> NULL;
            case BOOL -> BOOLEAN;
            default -> throw new DynamoToStructException("Unsupported attribute type: " + attr.type());
        };
    }

    private static byte[] attrToBytes(AttributeValue attr, boolean prefix, int depth) {
        if (depth > MAX_STRUCTURE_DEPTH) {
            throw new DynamoToStructException(
                "Depth of attribute structure to serialize exceeds limit of " + MAX_STRUCTURE_DEPTH);
        }
        byte[] base = switch (attr.type()) {
            case S -> utf8(attr.s());
            case N -> utf8(NumberNormalizer.normalizeNumber(attr.n()));
            case B -> attr.b().asByteArray();
            case SS -> stringSetToBytes(attr.ss());
            case NS -> numberSetToBytes(attr.ns());
            case BS -> binarySetToBytes(attr.bs());
            case M -> mapToBytes(attr.m(), depth);
            case L -> listToBytes(attr.l(), depth);
            case NUL -> new byte[0];
            case BOOL -> new byte[] {(byte) (attr.bool() ? 1 : 0)};
            default -> throw new DynamoToStructException("Unsupported attribute type: " + attr.type());
        };
        if (!prefix) {
            return base;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(TYPEID_LEN + LENGTH_LEN + base.length);
        out.writeBytes(attrToTypeId(attr));
        writeU32(out, base.length);
        out.writeBytes(base);
        return out.toByteArray();
    }

    private static byte[] stringSetToBytes(List<String> ss) {
        requireUniqueStrings(ss, "String Set had duplicate values");
        List<String> sorted = new ArrayList<>(ss);
        sorted.sort(DynamoToStruct::utf16Order);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeU32(out, sorted.size());
        for (String entry : sorted) {
            writeLengthPrefixed(out, utf8(entry));
        }
        return out.toByteArray();
    }

    private static byte[] numberSetToBytes(List<String> ns) {
        requireUniqueStrings(ns, "Number Set had duplicate values");
        List<String> normalized = new ArrayList<>(ns.size());
        for (String n : ns) {
            normalized.add(NumberNormalizer.normalizeNumber(n));
        }
        requireUniqueStrings(normalized, "Number Set had duplicate values after normalization.");
        normalized.sort(DynamoToStruct::utf16Order);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeU32(out, normalized.size());
        for (String entry : normalized) {
            writeLengthPrefixed(out, utf8(entry));
        }
        return out.toByteArray();
    }

    private static byte[] binarySetToBytes(List<SdkBytes> bs) {
        List<byte[]> entries = new ArrayList<>(bs.size());
        for (SdkBytes b : bs) {
            entries.add(b.asByteArray());
        }
        entries.sort(Arrays::compareUnsigned);
        for (int i = 1; i < entries.size(); i++) {
            if (Arrays.equals(entries.get(i - 1), entries.get(i))) {
                throw new DynamoToStructException("Binary Set had duplicate values");
            }
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeU32(out, entries.size());
        for (byte[] entry : entries) {
            writeLengthPrefixed(out, entry);
        }
        return out.toByteArray();
    }

    private static byte[] listToBytes(List<AttributeValue> list, int depth) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeU32(out, list.size());
        for (AttributeValue entry : list) {
            out.writeBytes(attrToBytes(entry, true, depth + 1));
        }
        return out.toByteArray();
    }

    private static byte[] mapToBytes(Map<String, AttributeValue> map, int depth) {
        List<String> keys = new ArrayList<>(map.keySet());
        keys.sort(DynamoToStruct::utf16Order);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeU32(out, keys.size());
        for (String key : keys) {
            byte[] keyBytes = utf8(key);
            if (keyBytes.length < 1 || keyBytes.length > MAX_ATTR_NAME_LEN) {
                throw new DynamoToStructException("Attribute name must be between 1 and 65535 UTF-8 bytes");
            }
            out.writeBytes(STRING);
            writeU32(out, keyBytes.length);
            out.writeBytes(keyBytes);
            out.writeBytes(attrToBytes(map.get(key), true, depth + 1));
        }
        return out.toByteArray();
    }

    private record Decoded(AttributeValue value, int consumed) {}

    private static Decoded decodeValue(byte[] data, int pos, byte[] typeId, int valueLen, int depth) {
        if (depth > MAX_STRUCTURE_DEPTH) {
            throw new DynamoToStructException(
                "Depth of attribute structure to deserialize exceeds limit of " + MAX_STRUCTURE_DEPTH);
        }
        if (valueLen < 0 || pos + valueLen > data.length) {
            throw new DynamoToStructException("Structured Data has too few bytes");
        }
        if (Arrays.equals(typeId, NULL)) {
            if (valueLen != 0) {
                throw new DynamoToStructException("NULL type did not have length zero");
            }
            return new Decoded(AttributeValue.fromNul(true), 0);
        }
        if (Arrays.equals(typeId, STRING)) {
            return new Decoded(AttributeValue.fromS(utf8Decode(data, pos, valueLen)), valueLen);
        }
        if (Arrays.equals(typeId, NUMBER)) {
            return new Decoded(AttributeValue.fromN(utf8Decode(data, pos, valueLen)), valueLen);
        }
        if (Arrays.equals(typeId, BINARY)) {
            return new Decoded(AttributeValue.fromB(SdkBytes.fromByteArray(slice(data, pos, valueLen))), valueLen);
        }
        if (Arrays.equals(typeId, BOOLEAN)) {
            if (valueLen != 1) {
                throw new DynamoToStructException("Boolean Structured Data has more than one byte");
            }
            byte b = data[pos];
            if (b == 0x00) {
                return new Decoded(AttributeValue.fromBool(false), 1);
            }
            if (b == 0x01) {
                return new Decoded(AttributeValue.fromBool(true), 1);
            }
            throw new DynamoToStructException("Boolean Structured Data had inappropriate value");
        }
        if (Arrays.equals(typeId, STRING_SET) || Arrays.equals(typeId, NUMBER_SET)) {
            return decodeStringSet(data, pos, valueLen, Arrays.equals(typeId, NUMBER_SET));
        }
        if (Arrays.equals(typeId, BINARY_SET)) {
            return decodeBinarySet(data, pos, valueLen);
        }
        if (Arrays.equals(typeId, LIST)) {
            return decodeList(data, pos, valueLen, depth);
        }
        if (Arrays.equals(typeId, MAP)) {
            return decodeMap(data, pos, valueLen, depth);
        }
        throw new DynamoToStructException("Unsupported TerminalTypeId");
    }

    private static Decoded decodeStringSet(byte[] data, int pos, int valueLen, boolean number) {
        int end = pos + valueLen;
        int count = readCount(data, pos, valueLen, "Set");
        int p = pos + LENGTH_LEN;
        List<String> entries = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            int entryLen = readEntryLength(data, p, end);
            p += LENGTH_LEN;
            requireBytes(p, entryLen, end);
            entries.add(utf8Decode(data, p, entryLen));
            p += entryLen;
        }
        AttributeValue value = number ? AttributeValue.fromNs(entries) : AttributeValue.fromSs(entries);
        return new Decoded(value, p - pos);
    }

    private static Decoded decodeBinarySet(byte[] data, int pos, int valueLen) {
        int end = pos + valueLen;
        int count = readCount(data, pos, valueLen, "Binary Set");
        int p = pos + LENGTH_LEN;
        List<SdkBytes> entries = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            int entryLen = readEntryLength(data, p, end);
            p += LENGTH_LEN;
            requireBytes(p, entryLen, end);
            entries.add(SdkBytes.fromByteArray(slice(data, p, entryLen)));
            p += entryLen;
        }
        return new Decoded(AttributeValue.fromBs(entries), p - pos);
    }

    private static Decoded decodeList(byte[] data, int pos, int valueLen, int depth) {
        int end = pos + valueLen;
        int count = readCount(data, pos, valueLen, "List");
        int p = pos + LENGTH_LEN;
        List<AttributeValue> entries = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            requireBytes(p, TYPEID_LEN + LENGTH_LEN, end);
            byte[] entryTypeId = slice(data, p, TYPEID_LEN);
            int entryLen = readU32(data, p + TYPEID_LEN);
            int valuePos = p + TYPEID_LEN + LENGTH_LEN;
            Decoded entry = decodeValue(data, valuePos, entryTypeId, entryLen, depth + 1);
            entries.add(entry.value());
            p = valuePos + entryLen;
        }
        return new Decoded(AttributeValue.fromL(entries), p - pos);
    }

    private static Decoded decodeMap(byte[] data, int pos, int valueLen, int depth) {
        int end = pos + valueLen;
        int count = readCount(data, pos, valueLen, "Map");
        int p = pos + LENGTH_LEN;
        Map<String, AttributeValue> map = new LinkedHashMap<>();
        for (int i = 0; i < count; i++) {
            requireBytes(p, TYPEID_LEN + LENGTH_LEN, end);
            byte[] keyType = slice(data, p, TYPEID_LEN);
            if (!Arrays.equals(keyType, STRING)) {
                throw new DynamoToStructException("Key of Map is not String");
            }
            int keyLen = readU32(data, p + TYPEID_LEN);
            int keyPos = p + TYPEID_LEN + LENGTH_LEN;
            requireBytes(keyPos, keyLen, end);
            String key = utf8Decode(data, keyPos, keyLen);
            int valTypePos = keyPos + keyLen;
            requireBytes(valTypePos, TYPEID_LEN + LENGTH_LEN, end);
            byte[] valueType = slice(data, valTypePos, TYPEID_LEN);
            int valueLenField = readU32(data, valTypePos + TYPEID_LEN);
            int valuePos = valTypePos + TYPEID_LEN + LENGTH_LEN;
            Decoded value = decodeValue(data, valuePos, valueType, valueLenField, depth + 1);
            map.put(key, value.value());
            p = valuePos + valueLenField;
        }
        return new Decoded(AttributeValue.fromM(map), p - pos);
    }

    private static int readCount(byte[] data, int pos, int valueLen, String what) {
        if (valueLen < LENGTH_LEN) {
            throw new DynamoToStructException(what + " Structured Data has less than 4 bytes");
        }
        return readU32(data, pos);
    }

    private static int readEntryLength(byte[] data, int pos, int end) {
        requireBytes(pos, LENGTH_LEN, end);
        return readU32(data, pos);
    }

    private static void requireBytes(int pos, int len, int end) {
        if (len < 0 || pos + len > end) {
            throw new DynamoToStructException("Structured Data has too few bytes");
        }
    }

    private static int readU32(byte[] data, int pos) {
        int value = ((data[pos] & 0xFF) << 24)
            | ((data[pos + 1] & 0xFF) << 16)
            | ((data[pos + 2] & 0xFF) << 8)
            | (data[pos + 3] & 0xFF);
        if (value < 0) {
            throw new DynamoToStructException("Length was too big");
        }
        return value;
    }

    private static void writeU32(ByteArrayOutputStream out, int n) {
        out.write((n >>> 24) & 0xFF);
        out.write((n >>> 16) & 0xFF);
        out.write((n >>> 8) & 0xFF);
        out.write(n & 0xFF);
    }

    private static void writeLengthPrefixed(ByteArrayOutputStream out, byte[] bytes) {
        writeU32(out, bytes.length);
        out.writeBytes(bytes);
    }

    private static int utf16Order(String a, String b) {
        return a.compareTo(b);
    }

    private static void requireUniqueStrings(List<String> values, String message) {
        Set<String> seen = new HashSet<>();
        for (String value : values) {
            if (!seen.add(value)) {
                throw new DynamoToStructException(message);
            }
        }
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static String utf8Decode(byte[] data, int pos, int len) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(data, pos, len))
                .toString();
        } catch (CharacterCodingException e) {
            throw new DynamoToStructException("Invalid UTF-8 in encoded value");
        }
    }

    private static byte[] slice(byte[] data, int pos, int len) {
        return Arrays.copyOfRange(data, pos, pos + len);
    }
}
