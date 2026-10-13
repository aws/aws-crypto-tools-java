package software.amazon.cryptography.dbesdk.dynamodbencryption;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

/**
 * A compound beacon (CompoundBeacon.dfy): a value assembled from ordered {@link BeaconPart}s,
 * each contributing {@code prefix + partValue}, joined on a split character, choosing the
 * first {@code constructor} whose required parts are all available.
 *
 * <p>This is the write-value core (the Dafny {@code hash}/{@code TryConstructors}/
 * {@code TryConstructor}/{@code PartValueCalc}). The read-path query helpers
 * ({@code GetBeaconValue}, prefix-based part parsing) are a separate slice; see the B3
 * behavior spec.
 */
public final class CompoundBeacon {

    /** One part of a constructor, optionally required for that constructor to succeed. */
    public record ConstructorPart(BeaconPart part, boolean required) {
    }

    private final String name;
    private final char split;
    private final List<BeaconPart> parts;
    private final List<List<ConstructorPart>> constructors;

    private CompoundBeacon(
            String name, char split, List<BeaconPart> parts, List<List<ConstructorPart>> constructors) {
        this.name = name;
        this.split = split;
        this.parts = parts;
        this.constructors = constructors;
    }

    /**
     * Build a compound beacon. Every part prefix must be non-empty and no prefix may be a
     * prefix of another (so a value's prefix maps to exactly one part). An empty
     * constructor list defaults to a single constructor of all parts, each required, in
     * order.
     *
     * @throws BeaconException if a prefix is empty or one prefix is a prefix of another
     */
    public static CompoundBeacon create(
            String name, char split, List<BeaconPart> parts, List<List<ConstructorPart>> constructors) {
        validatePrefixes(parts);
        List<List<ConstructorPart>> cons = new ArrayList<>();
        if (constructors.isEmpty()) {
            cons.add(defaultConstructor(parts));
        } else {
            for (List<ConstructorPart> c : constructors) {
                cons.add(List.copyOf(c));
            }
        }
        return new CompoundBeacon(name, split, List.copyOf(parts), List.copyOf(cons));
    }

    public String name() {
        return name;
    }

    /**
     * Whether a query value is comparable with {@code <}/{@code <=}/{@code >}/{@code >=}
     * (CompoundBeacon.dfy {@code IsLessThanComparable} over {@code Split}): after skipping
     * leading signed pieces, at most one piece may remain, and if one remains it must be a
     * bare prefix. An inequality that would compare across an encrypted part's truncated
     * hash is not well-ordered, so such a query is rejected.
     */
    public boolean isLessThanComparable(String value) {
        return isLessThanComparable(VirtualTransform.splitOn(value, split));
    }

    /**
     * Whether two query values are BETWEEN-comparable (CompoundBeacon.dfy {@code CanBetween}):
     * drop the parts common to both, then require each remainder to be
     * {@link #isLessThanComparable(String) LessThanComparable}.
     */
    public boolean isBetweenComparable(String leftValue, String rightValue) {
        List<String> left = VirtualTransform.splitOn(leftValue, split);
        List<String> right = VirtualTransform.splitOn(rightValue, split);
        int common = 0;
        while (common < left.size() && common < right.size() && left.get(common).equals(right.get(common))) {
            common++;
        }
        return isLessThanComparable(left.subList(common, left.size()))
            && isLessThanComparable(right.subList(common, right.size()));
    }

    private boolean isLessThanComparable(List<String> pieces) {
        List<String> rest = skipSignedPieces(pieces);
        if (rest.isEmpty()) {
            return true;
        }
        if (rest.size() != 1) {
            return false;
        }
        return findPart(rest.get(0)).prefix().equals(rest.get(0));
    }

    // Drop leading pieces belonging to signed parts; stop at the first encrypted part.
    private List<String> skipSignedPieces(List<String> pieces) {
        int i = 0;
        while (i < pieces.size() && !(findPart(pieces.get(i)) instanceof BeaconPart.Encrypted)) {
            i++;
        }
        return pieces.subList(i, pieces.size());
    }

    /**
     * Whether this compound beacon has any encrypted part (CompoundBeacon.dfy
     * {@code isEncrypted}, i.e. {@code numSigned < |parts|}). An encrypted compound beacon
     * is written to the encrypted output as {@code aws_dbe_b_<name>}; a fully-signed one is
     * signed in before encryption as {@code <name>}.
     */
    public boolean isEncrypted() {
        return parts.stream().anyMatch(part -> part instanceof BeaconPart.Encrypted);
    }

    /**
     * The stored attributes this compound beacon reads: every part's fields in order
     * (CompoundBeacon.dfy {@code GetFields}, a flatten over the parts). Duplicates and
     * order are preserved.
     */
    public List<String> getFields(Map<String, VirtualField> virtualFields) {
        List<String> fields = new ArrayList<>();
        for (BeaconPart part : parts) {
            fields.addAll(part.getFields(virtualFields));
        }
        return List.copyOf(fields);
    }

    /**
     * The compound beacon value for an item: the first constructor whose required parts are
     * all present, assembled; empty if no constructor succeeds (no beacon written).
     *
     * @param hmacKeys per-beacon HMAC keys for encrypted parts, or {@code null} for the
     *                 keyless "naked" value (all parts contribute {@code prefix + plaintext})
     */
    public Optional<String> getValue(
            Map<String, AttributeValue> item, Map<String, VirtualField> virtualFields,
            Map<String, byte[]> hmacKeys, int partition) {
        for (List<ConstructorPart> constructor : constructors) {
            Optional<String> value = tryConstructor(constructor, item, virtualFields, hmacKeys, partition);
            if (value.isPresent()) {
                return value;
            }
        }
        return Optional.empty();
    }

    // Assemble one constructor, or empty if a required part is absent (try the next one).
    private Optional<String> tryConstructor(
            List<ConstructorPart> constructor, Map<String, AttributeValue> item,
            Map<String, VirtualField> virtualFields, Map<String, byte[]> hmacKeys, int partition) {
        StringBuilder acc = new StringBuilder();
        boolean any = false;
        for (ConstructorPart constructorPart : constructor) {
            BeaconPart part = constructorPart.part();
            Optional<String> located = part.getString(item, virtualFields);
            if (located.isPresent()) {
                String value = located.get();
                if (value.indexOf(split) >= 0) {
                    throw new BeaconException("Value '" + value + "' for beacon part " + part.name()
                        + " contains the split character '" + split + "'.");
                }
                String partValue = hmacKeys == null
                    ? part.prefix() + value
                    : part.partValue(value, hmacKeys, partition);
                if (any) {
                    acc.append(split);
                }
                acc.append(partValue);
                any = true;
            } else if (constructorPart.required()) {
                return Optional.empty();
            }
        }
        if (!any) {
            throw new BeaconException("Internal Error : Empty beacon created.");
        }
        return Optional.of(acc.toString());
    }

    // A value's prefix must identify exactly one part, so no prefix may be a prefix of
    // another (Dafny ValidPrefixSet / OkPrefixStringPair).
    private static void validatePrefixes(List<BeaconPart> parts) {
        for (BeaconPart part : parts) {
            if (part.prefix().isEmpty()) {
                throw new BeaconException("Beacon part " + part.name() + " has an empty prefix.");
            }
        }
        for (int i = 0; i < parts.size(); i++) {
            for (int j = i + 1; j < parts.size(); j++) {
                String a = parts.get(i).prefix();
                String b = parts.get(j).prefix();
                if (a.startsWith(b) || b.startsWith(a)) {
                    throw new BeaconException(
                        "Compound beacon prefixes '" + a + "' and '" + b + "' overlap; "
                            + "no prefix may be a prefix of another.");
                }
            }
        }
    }

    private static List<ConstructorPart> defaultConstructor(List<BeaconPart> parts) {
        List<ConstructorPart> constructor = new ArrayList<>(parts.size());
        for (BeaconPart part : parts) {
            constructor.add(new ConstructorPart(part, true));
        }
        return List.copyOf(constructor);
    }

    // --- read path (query) -----------------------------------------------

    /**
     * The beaconized form of a compound query value (CompoundBeacon.dfy GetBeaconValue):
     * split on the split char, replace each piece's value with its part value (encrypted
     * pieces hashed, signed pieces plaintext, each keeping its prefix), and rejoin. For a
     * non-equality query whose last piece is a bare prefix (e.g. begins_with), the last
     * piece is kept raw so the DB can still range/prefix match it.
     *
     * @throws BeaconException if the value is not a string, a piece matches no part, or the
     *     pieces do not match any constructor's part order
     */
    public AttributeValue getBeaconValue(
            AttributeValue value, Map<String, byte[]> hmacKeys, boolean forEquality, int partition) {
        if (value.type() != AttributeValue.Type.S) {
            throw new BeaconException("CompoundBeacon " + name + " can only be queried as a string.");
        }
        List<String> pieces = VirtualTransform.splitOn(value.s(), split);
        List<BeaconPart> partsUsed = new ArrayList<>(pieces.size());
        for (String piece : pieces) {
            partsUsed.add(findPart(piece));
        }
        validatePartOrder(partsUsed, value.s());
        List<String> beaconPieces = new ArrayList<>(pieces.size());
        for (String piece : pieces) {
            beaconPieces.add(calcPiece(piece, hmacKeys, partition));
        }
        String lastPiece = pieces.get(pieces.size() - 1);
        if (!forEquality && lastPiece.equals(findPart(lastPiece).prefix())) {
            beaconPieces.set(beaconPieces.size() - 1, lastPiece);
        }
        return AttributeValue.fromS(String.join(String.valueOf(split), beaconPieces));
    }

    /** The single part whose prefix begins {@code value}; fails if none (or several) match. */
    public BeaconPart findPart(String value) {        BeaconPart found = null;
        for (BeaconPart part : parts) {
            if (value.startsWith(part.prefix())) {
                if (found != null) {
                    throw new BeaconException(
                        "Internal error. Multiple parts for beacon " + name + " matched prefix of " + value);
                }
                found = part;
            }
        }
        if (found == null) {
            throw new BeaconException(
                "Value " + value + " for beacon " + name + " does not match the prefix of any configured part.");
        }
        return found;
    }

    /**
     * The key id a multi-tenant query embeds in this beacon (FilterExpr.dfy
     * {@code KeyIdFromPart}): if exactly one signed part reads {@code keyIdField} and the
     * query value has exactly one piece carrying that part's prefix, return that piece
     * with the prefix stripped; otherwise empty. The caller supplies the key-id field from
     * the beacon version's key source.
     */
    public Optional<String> keyIdFromValue(String keyIdField, String value) {
        BeaconPart.Signed keyPart = null;
        for (BeaconPart part : parts) {
            if (part instanceof BeaconPart.Signed signed && signed.loc().rootKey().equals(keyIdField)) {
                if (keyPart != null) {
                    return Optional.empty();
                }
                keyPart = signed;
            }
        }
        if (keyPart == null) {
            return Optional.empty();
        }
        String prefix = keyPart.prefix();
        String match = null;
        for (String piece : VirtualTransform.splitOn(value, split)) {
            if (piece.startsWith(prefix)) {
                if (match != null) {
                    return Optional.empty();
                }
                match = piece;
            }
        }
        return match == null ? Optional.empty() : Optional.of(match.substring(prefix.length()));
    }

    // The part value for a query piece: strip the matched prefix, then prefix + (hash|plaintext).
    private String calcPiece(String piece, Map<String, byte[]> hmacKeys, int partition) {        BeaconPart part = findPart(piece);
        return part.partValue(piece.substring(part.prefix().length()), hmacKeys, partition);
    }

    // The parsed sequence of parts must match some constructor's order; optional parts may
    // be skipped, but once a part is matched the remainder must follow directly.
    private void validatePartOrder(List<BeaconPart> inParts, String original) {
        for (List<ConstructorPart> constructor : constructors) {
            if (canConstruct(constructor, 0, inParts, 0, false)) {
                return;
            }
        }
        throw new BeaconException("Compound Beacon value '" + original
            + "' cannot be constructed from any available constructor for " + name + ".");
    }

    private static boolean canConstruct(
            List<ConstructorPart> constructor, int ci, List<BeaconPart> inParts, int pi, boolean matched) {
        if (pi == inParts.size()) {
            return true;
        }
        if (ci == constructor.size()) {
            return false;
        }
        if (constructor.get(ci).part().equals(inParts.get(pi))) {
            return canConstruct(constructor, ci + 1, inParts, pi + 1, true);
        }
        if (!constructor.get(ci).required() || !matched) {
            return canConstruct(constructor, ci + 1, inParts, pi, matched);
        }
        return false;
    }
}
