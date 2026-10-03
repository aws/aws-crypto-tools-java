package software.amazon.cryptography.dbesdk.dynamodbencryption;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

/**
 * A terminal location: the parsed form of a beacon's source-value path into a DynamoDB
 * item (BeaconValueLocation behavior spec §1–§3). A location string like
 * {@code "a.b[3].c"} parses to a list of {@link Selector}s whose first element is always
 * a map key; locating a value walks the item along those selectors.
 *
 * <p>Behavioral parity target: {@code TermLoc} in
 * DynamoDbEncryption/dafny/DynamoDbEncryption/src/TermLoc.dfy. Expression-attribute-name
 * alias resolution (the {@code names} argument in Dafny) is a query-rewrite concern; the
 * write-time path never supplies aliases, so it is not ported here (spec §7).
 */
public final class TermLoc {

    /** One navigation step: into a map by key, or into a list by index. */
    sealed interface Selector permits MapKey, ListIndex {}

    record MapKey(String key) implements Selector {}

    record ListIndex(long pos) implements Selector {}

    // Largest value GetNumber accepts for a list index (Dafny TermLoc.dfy GetNumber);
    // a larger index fails parsing rather than silently wrapping.
    private static final long MAX_LIST_INDEX = 0xfff_ffff_ffff_ffffL;

    private final List<Selector> selectors;

    private TermLoc(List<Selector> selectors) {
        this.selectors = selectors;
    }

    /**
     * Parse a terminal-location string. The first segment is a bare field name (up to the
     * first {@code .} or {@code [}); {@code .name} is a map lookup; {@code [n]} is a list
     * index. The result always begins with a map key, so a bare {@code "foo"} parses to a
     * single map selector.
     *
     * @throws BeaconException if the string is empty, a {@code [} segment is unterminated,
     *     or a list index is non-numeric or exceeds the maximum
     */
    public static TermLoc make(String loc) {
        if (loc.isEmpty()) {
            throw new BeaconException("Path specification must not be empty.");
        }
        int pos = findStartOfNext(loc);
        if (pos < 0) {
            return new TermLoc(List.of(new MapKey(loc)));
        }
        List<Selector> selectors = new ArrayList<>();
        selectors.add(new MapKey(loc.substring(0, pos)));
        selectors.addAll(parseSelectors(loc.substring(pos)));
        return new TermLoc(selectors);
    }

    /**
     * The located attribute value, or empty if it is absent. Every navigation miss — a
     * missing key, an out-of-range index, or a selector that does not match the value's
     * shape — is reported as absent, not an error (BeaconValueLocation spec §3): a beacon
     * is simply not written for an item that lacks the field.
     */
    public Optional<AttributeValue> termToAttr(Map<String, AttributeValue> item) {
        AttributeValue current = item.get(firstKey());
        for (int i = 1; current != null && i < selectors.size(); i++) {
            current = step(current, selectors.get(i));
        }
        return Optional.ofNullable(current);
    }

    /**
     * The located attribute serialized to its top-level value bytes (via
     * {@link DynamoToStruct}), or empty if the attribute is absent. A genuine
     * serialization problem surfaces as a {@link DynamoToStructException}, distinct from
     * the empty "absent" result.
     */
    public Optional<byte[]> termToBytes(Map<String, AttributeValue> item) {
        return termToAttr(item).map(attr -> DynamoToStruct.attrToStructured(attr).value());
    }

    private String firstKey() {
        return ((MapKey) selectors.get(0)).key();
    }

    List<Selector> selectors() {
        return selectors;
    }

    // One navigation step, or null when the selector cannot be followed (wrong shape,
    // missing key, or out-of-range index) — all of which mean "absent" to the caller.
    private static AttributeValue step(AttributeValue value, Selector selector) {
        return switch (value.type()) {
            case L -> selector instanceof ListIndex index
                    && index.pos() < value.l().size()
                ? value.l().get((int) index.pos())
                : null;
            case M -> selector instanceof MapKey key ? value.m().get(key.key()) : null;
            default -> null;
        };
    }

    // Index of the first '.' or '[', or -1 if the string contains neither.
    private static int findStartOfNext(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '.' || c == '[') {
                return i;
            }
        }
        return -1;
    }

    // Parse the selectors following the field name. The input starts with '.' or '['; each
    // segment runs up to the next '.' or '['.
    private static List<Selector> parseSelectors(String s) {
        List<Selector> acc = new ArrayList<>();
        while (true) {
            int next = findStartOfNext(s.substring(1));
            int end = next < 0 ? s.length() : next + 1;
            acc.add(parseSelector(s.substring(0, end)));
            if (next < 0) {
                return acc;
            }
            s = s.substring(end);
        }
    }

    // Parse one segment: '.name' -> map key, '[n]' -> list index.
    private static Selector parseSelector(String s) {
        if (s.charAt(0) == '.') {
            return new MapKey(s.substring(1));
        }
        if (s.charAt(s.length() - 1) != ']') {
            throw new BeaconException("List index must end with ]");
        }
        return new ListIndex(parseIndex(s.substring(1, s.length() - 1)));
    }

    private static long parseIndex(String s) {
        long acc = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                throw new BeaconException("Unexpected character in number : " + c);
            }
            // Dafny accumulates in uint64; compare unsigned so a value past the signed
            // long range is still bounded by MAX_LIST_INDEX rather than wrapping negative.
            if (Long.compareUnsigned(acc, MAX_LIST_INDEX) >= 0) {
                throw new BeaconException("Number is too big for list index : " + s);
            }
            acc = acc * 10 + (c - '0');
        }
        return acc;
    }
}
