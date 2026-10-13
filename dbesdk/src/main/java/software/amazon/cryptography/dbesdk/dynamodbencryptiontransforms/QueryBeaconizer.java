package software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbesdk.dynamodbencryption.Beacon;
import software.amazon.cryptography.dbesdk.dynamodbencryption.BeaconVersion;
import software.amazon.cryptography.dbesdk.dynamodbencryption.CompoundBeacon;
import software.amazon.cryptography.dbesdk.dynamodbencryption.MaybeKeyMap;
import software.amazon.cryptography.dbesdk.dynamodbencryption.TermLoc;
import software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms.ExpressionTokenizer.Token;

/**
 * Rewrites a Query/Scan's condition expressions into beacon form (DynamoDBFilterExpr
 * {@code Beaconize}): each queried beacon attribute becomes {@code aws_dbe_b_<name>} and each
 * value compared against it becomes that beacon's value, so DynamoDB can match on the stored
 * beacons. The rewrite walks the parsed tokens ({@link ExpressionTokenizer}); which beacon a
 * value refers to is decided by the surrounding comparison tokens ({@link #beaconForValue}).
 *
 * <p>Because beacons are truncated hashes, a beacon query returns a superset of the true
 * matches; the output filter (a separate step) re-filters the decrypted items. This class is
 * only the input rewrite — the two must both run for an exact result.
 *
 * <p>This is the single-partition base case: the key id is resolved by the caller and the
 * partition is fixed. The multi-partition OR fan-out ({@code DoBeaconize}) and the
 * multi-tenant key-id extraction from the query are separate features.
 */
final class QueryBeaconizer {

    private QueryBeaconizer() {
    }

    /** A value's beacon context: which beacon (if any) it compares against, and how. */
    private record EqualityBeacon(Optional<Beacon> beacon, boolean forEquality, boolean forContains) {
        static EqualityBeacon none() {
            return new EqualityBeacon(Optional.empty(), true, false);
        }
    }

    /** The rewritten tokens plus the updated value and name maps (Dafny {@code ParsedContext}). */
    record ParsedContext(List<Token> expr, Map<String, AttributeValue> values, Map<String, String> names) {
    }

    /**
     * Rewrite the key and filter expressions of {@code ctx} into beacon form, under the
     * resolved beacon keys ({@code keys}) and write/query {@code partition}. Returns a new
     * context with the rewritten expressions, the updated value map, and the (possibly
     * remapped) names map. An empty context (no key or filter expression) is returned
     * unchanged.
     */
    static ExprContext beaconize(BeaconVersion b, ExprContext ctx, MaybeKeyMap keys, int partition) {
        if (ctx.keyExpr() == null && ctx.filterExpr() == null) {
            return ctx;
        }
        Map<String, AttributeValue> oldValues = ctx.values() != null ? ctx.values() : Map.of();
        Map<String, AttributeValue> newValues = Map.of();
        Map<String, String> names = ctx.names();
        String newKeyExpr = ctx.keyExpr();
        String newFilterExpr = ctx.filterExpr();

        if (ctx.keyExpr() != null) {
            ParsedContext pc = beaconizeParsedExpr(
                b, ExpressionTokenizer.parse(ctx.keyExpr()), oldValues, names, keys, newValues, partition);
            newKeyExpr = ExpressionTokenizer.toExpression(pc.expr());
            newValues = pc.values();
            names = pc.names();
        }
        if (ctx.filterExpr() != null) {
            ParsedContext pc = beaconizeParsedExpr(
                b, ExpressionTokenizer.parse(ctx.filterExpr()), oldValues, names, keys, newValues, partition);
            newFilterExpr = ExpressionTokenizer.toExpression(pc.expr());
            newValues = pc.values();
            names = pc.names();
        }
        return new ExprContext(newKeyExpr, newFilterExpr, newValues.isEmpty() ? null : newValues, names);
    }

    // Walk the tokens: rewrite each beacon attr to its beacon name, each compared value to
    // its beacon value, accumulating the rewritten tokens, the new values, and any #name
    // remappings (BeaconizeParsedExpr). Shared by the input rewrite (keyed) and the output
    // filter (DontUseKeys, where values are left plaintext and size()/attribute_type() over
    // a beacon is kept rather than rejected).
    static ParsedContext beaconizeParsedExpr(
            BeaconVersion b, List<Token> expr, Map<String, AttributeValue> oldValues,
            Map<String, String> names, MaybeKeyMap keys, Map<String, AttributeValue> newValues, int partition) {
        List<Token> acc = new ArrayList<>(expr.size());
        Map<String, String> curNames = names;
        Map<String, AttributeValue> curValues = new LinkedHashMap<>(newValues);

        for (int pos = 0; pos < expr.size(); pos++) {
            Token token = expr.get(pos);
            if (token instanceof Token.Attr attr) {
                boolean indirect = attr.s().startsWith("#");
                if (indirect && (curNames == null || !curNames.containsKey(attr.s()))) {
                    throw new DynamoDbEncryptionTransformsException(
                        "Name " + attr.s() + " not in ExpressionAttributeNameMap.");
                }
                String oldName = indirect ? curNames.get(attr.s()) : attr.s();
                boolean exclude = keys instanceof MaybeKeyMap.DontUseKeys && !isAllowedOnBeaconPred(expr, pos);
                if (b.isBeacon(oldName) && !exclude) {
                    isAllowedOnBeacon(expr, pos, oldName);
                    if (opNeedsBeacon(expr, pos)) {
                        String newName = b.getBeacon(oldName).beaconName();
                        if (indirect) {
                            curNames = new LinkedHashMap<>(curNames);
                            curNames.put(attr.s(), newName);
                            acc.add(token);
                        } else {
                            acc.add(new Token.Attr(newName, TermLoc.ofKey(newName)));
                        }
                    } else {
                        acc.add(token);
                    }
                } else {
                    acc.add(token);
                }
            } else if (token instanceof Token.Value value) {
                String name = value.s();
                if (!oldValues.containsKey(name)) {
                    throw new DynamoDbEncryptionTransformsException(
                        name + " not found in ExpressionAttributeValueMap");
                }
                AttributeValue oldValue = oldValues.get(name);
                EqualityBeacon eb = beaconForValue(b, expr, pos, curNames, oldValues);
                AttributeValue newValue = eb.beacon().isEmpty()
                    ? oldValue
                    : eb.beacon().get().getBeaconValue(oldValue, keys, eb.forEquality(), eb.forContains(), partition);
                if (curValues.containsKey(name) && !curValues.get(name).equals(newValue)) {
                    throw new DynamoDbEncryptionTransformsException(
                        name + " used in two different contexts, which is not allowed.");
                }
                curValues.put(name, newValue);
                acc.add(token);
            } else {
                acc.add(token);
            }
        }
        return new ParsedContext(acc, curValues, curNames);
    }

    // The value at expr[pos] compares against some beacon, decided by the surrounding tokens
    // (BeaconForValue). The recognized shapes are the comparison, contains/begins_with,
    // BETWEEN, and IN forms; anything else leaves the value unbeaconized.
    private static EqualityBeacon beaconForValue(
            BeaconVersion b, List<Token> expr, int pos, Map<String, String> names,
            Map<String, AttributeValue> values) {
        int n = expr.size();
        // value <cmp> ATTR
        if (pos + 2 < n && isComp(expr.get(pos + 1)) && hasBeacon(b, expr.get(pos + 2), names)) {
            return getBeacon(b, expr.get(pos + 2), expr.get(pos + 1), expr.get(pos), names, values);
        }
        // ATTR <cmp> value
        if (pos >= 2 && isComp(expr.get(pos - 1)) && hasBeacon(b, expr.get(pos - 2), names)) {
            return getBeacon(b, expr.get(pos - 2), expr.get(pos - 1), expr.get(pos), names, values);
        }
        // contains(ATTR, value / begins_with(ATTR, value
        if (pos >= 4 && (is(expr, pos - 4, Token.Symbol.CONTAINS) || is(expr, pos - 4, Token.Symbol.BEGINS_WITH))
                && is(expr, pos - 3, Token.Symbol.OPEN) && hasBeacon(b, expr.get(pos - 2), names)
                && is(expr, pos - 1, Token.Symbol.COMMA)) {
            return getBeacon(b, expr.get(pos - 2), expr.get(pos - 4), expr.get(pos), names, values);
        }
        // contains(value, ATTR / begins_with(value, ATTR
        if (pos >= 2 && pos < n - 2 && (is(expr, pos - 2, Token.Symbol.CONTAINS) || is(expr, pos - 2, Token.Symbol.BEGINS_WITH))
                && is(expr, pos - 1, Token.Symbol.OPEN) && hasBeacon(b, expr.get(pos + 2), names)
                && is(expr, pos + 1, Token.Symbol.COMMA)) {
            return getBeacon(b, expr.get(pos + 2), expr.get(pos - 2), expr.get(pos), names, values);
        }
        // ATTR BETWEEN value AND *
        if (pos >= 2 && pos < n - 2 && is(expr, pos - 1, Token.Symbol.BETWEEN)
                && hasBeacon(b, expr.get(pos - 2), names) && isValue(expr.get(pos + 2))) {
            return getBetweenBeacon(b, expr.get(pos - 2), expr.get(pos - 1), expr.get(pos), expr.get(pos + 2), names, values);
        }
        // ATTR BETWEEN * AND value
        if (pos >= 4 && is(expr, pos - 1, Token.Symbol.AND) && is(expr, pos - 3, Token.Symbol.BETWEEN)
                && hasBeacon(b, expr.get(pos - 4), names) && isValue(expr.get(pos - 2))) {
            return getBetweenBeacon(b, expr.get(pos - 4), expr.get(pos - 3), expr.get(pos - 2), expr.get(pos), names, values);
        }
        // ATTR IN value, value, ...
        Optional<Integer> inPos = getInPos(expr, pos);
        if (inPos.isPresent() && hasBeacon(b, expr.get(inPos.get() - 1), names)) {
            return getBeacon(b, expr.get(inPos.get() - 1), expr.get(inPos.get()), expr.get(pos), names, values);
        }
        return EqualityBeacon.none();
    }

    // The beacon that attr token t refers to, with the equality/contains flags for op.
    private static EqualityBeacon getBeacon(
            BeaconVersion b, Token t, Token op, Token value, Map<String, String> names,
            Map<String, AttributeValue> values) {
        Beacon beacon = getBeacon2(b, t, names);
        canBeacon(beacon, op, ((Token.Value) value).s(), values);
        return new EqualityBeacon(Optional.of(beacon), isEquality(op), op == Token.Symbol.CONTAINS);
    }

    // The beacon that a BETWEEN's attr refers to, after validating the two limits are
    // BETWEEN-comparable.
    private static EqualityBeacon getBetweenBeacon(
            BeaconVersion b, Token t, Token op, Token leftValue, Token rightValue,
            Map<String, String> names, Map<String, AttributeValue> values) {
        Beacon beacon = getBeacon2(b, t, names);
        canBetween(beacon, ((Token.Value) leftValue).s(), ((Token.Value) rightValue).s(), values);
        return new EqualityBeacon(Optional.of(beacon), false, false);
    }

    // The beacon for attr token t, or an error if t is an encrypted field with no (usable)
    // beacon or a PartOnly beacon used on its own (GetBeacon2). Caller guarantees hasBeacon.
    private static Beacon getBeacon2(BeaconVersion b, Token t, Map<String, String> names) {
        String name = realName(((Token.Attr) t).s());
        if (b.isBeacon(name)) {
            Beacon beacon = b.getBeacon(name);
            if (beacon.isPartOnly()) {
                throw new DynamoDbEncryptionTransformsException("Field " + name
                    + " is encrypted, and has a PartOnly beacon, and so can only be used as part of a compound beacon.");
            }
            return beacon;
        }
        if (names != null && names.containsKey(name) && b.isBeacon(realName(names.get(name)))) {
            return b.getBeacon(realName(names.get(name)));
        }
        if (b.encryptedFields().contains(name)) {
            throw new DynamoDbEncryptionTransformsException(
                "Field " + name + " is encrypted, and cannot be searched without a beacon.");
        }
        throw new DynamoDbEncryptionTransformsException(
            "Field " + realName(names.get(name)) + " is encrypted, and cannot be searched without a beacon.");
    }

    // Does attr token t name (or alias) a beacon or an encrypted field? (HasBeacon)
    private static boolean hasBeacon(BeaconVersion b, Token t, Map<String, String> names) {
        if (!(t instanceof Token.Attr attr)) {
            return false;
        }
        String name = realName(attr.s());
        boolean aliased = names != null && names.containsKey(name);
        return b.isBeacon(name)
            || (aliased && b.isBeacon(realName(names.get(name))))
            || b.encryptedFields().contains(name)
            || (aliased && b.encryptedFields().contains(realName(names.get(name))));
    }

    // Validate that op may be used with this beacon, failing for operations a beacon can't
    // support (CanBeacon). A standard beacon supports only equality and contains; a compound
    // beacon's inequality requires a LessThanComparable value.
    private static void canBeacon(Beacon beacon, Token op, String valueName, Map<String, AttributeValue> values) {
        if (beacon instanceof Beacon.Standard) {
            canStandardBeacon(op);
        } else {
            String value = getStringFromValue(valueName, values, beacon);
            if (op == Token.Symbol.LT || op == Token.Symbol.GT || op == Token.Symbol.LE || op == Token.Symbol.GE) {
                CompoundBeacon compound = ((Beacon.Compound) beacon).beacon();
                if (!compound.isLessThanComparable(value)) {
                    throw new DynamoDbEncryptionTransformsException("The operation '" + op.text()
                        + "' cannot be used with a compound beacon, unless the value is LessThanComparable : " + value);
                }
            }
        }
    }

    private static void canStandardBeacon(Token op) {
        if (op == Token.Symbol.NE || op == Token.Symbol.LT || op == Token.Symbol.GT || op == Token.Symbol.LE
                || op == Token.Symbol.GE || op == Token.Symbol.BETWEEN || op == Token.Symbol.BEGINS_WITH) {
            throw new DynamoDbEncryptionTransformsException(
                "The operation '" + op.text() + "' cannot be used with a standard beacon.");
        }
    }

    private static void canBetween(Beacon beacon, String leftName, String rightName, Map<String, AttributeValue> values) {
        if (beacon instanceof Beacon.Standard) {
            throw new DynamoDbEncryptionTransformsException(
                "The operation BETWEEN cannot be used with a standard beacon.");
        }
        String leftValue = getStringFromValue(leftName, values, beacon);
        String rightValue = getStringFromValue(rightName, values, beacon);
        if (!((Beacon.Compound) beacon).beacon().isBetweenComparable(leftValue, rightValue)) {
            throw new DynamoDbEncryptionTransformsException(
                "To use BETWEEN with a compound beacon, the part after any common prefix must be LessThanComparable : "
                    + "BETWEEN " + leftValue + " AND " + rightValue);
        }
    }

    // The string a value name resolves to, required for a compound beacon query (GetStringFromValue).
    private static String getStringFromValue(String valueName, Map<String, AttributeValue> values, Beacon beacon) {
        if (!values.containsKey(valueName)) {
            throw new DynamoDbEncryptionTransformsException(
                "Value " + valueName + " used in query string, but not supplied in value map.");
        }
        AttributeValue value = values.get(valueName);
        if (value.type() != AttributeValue.Type.S) {
            throw new DynamoDbEncryptionTransformsException("Value " + valueName + " supplied for compound beacon "
                + beacon.name() + " is of type " + value.type() + " but must be of type S (string).");
        }
        return value.s();
    }

    // If expr is "ATTR IN ( value, value, ... )" and expr[pos] is one of the values, return
    // the index of IN; else empty (GetInPos).
    private static Optional<Integer> getInPos(List<Token> expr, int pos) {
        while (pos >= 3) {
            if (is(expr, pos - 1, Token.Symbol.OPEN) && is(expr, pos - 2, Token.Symbol.IN)) {
                return Optional.of(pos - 2);
            }
            if (is(expr, pos - 1, Token.Symbol.COMMA) && isValue(expr.get(pos - 2))) {
                pos -= 2;
                continue;
            }
            return Optional.empty();
        }
        return Optional.empty();
    }

    // False if the beacon attr is the operand of attribute_exists/attribute_not_exists —
    // those operate on the encrypted field itself, not its beacon (OpNeedsBeacon).
    private static boolean opNeedsBeacon(List<Token> expr, int pos) {
        if (pos < 2 || !is(expr, pos - 1, Token.Symbol.OPEN)) {
            return true;
        }
        Token fn = expr.get(pos - 2);
        return fn != Token.Symbol.ATTRIBUTE_EXISTS && fn != Token.Symbol.ATTRIBUTE_NOT_EXISTS;
    }

    // True unless the beacon attr is the operand of size()/attribute_type(), which can
    // operate on neither the encrypted value nor its beacon (IsAllowedOnBeaconPred).
    private static boolean isAllowedOnBeaconPred(List<Token> expr, int pos) {
        if (pos < 2 || !is(expr, pos - 1, Token.Symbol.OPEN)) {
            return true;
        }
        Token fn = expr.get(pos - 2);
        return fn != Token.Symbol.ATTRIBUTE_TYPE && fn != Token.Symbol.SIZE;
    }

    private static void isAllowedOnBeacon(List<Token> expr, int pos, String name) {
        if (!isAllowedOnBeaconPred(expr, pos)) {
            throw new DynamoDbEncryptionTransformsException("Function " + expr.get(pos - 2).text()
                + " cannot be used on encrypted fields, but it is being used with " + name);
        }
    }

    private static boolean isComp(Token t) {
        return t == Token.Symbol.EQ || t == Token.Symbol.NE || t == Token.Symbol.LT
            || t == Token.Symbol.GT || t == Token.Symbol.LE || t == Token.Symbol.GE;
    }

    private static boolean isEquality(Token t) {
        return t == Token.Symbol.EQ || t == Token.Symbol.NE || t == Token.Symbol.IN;
    }

    private static boolean isValue(Token t) {
        return t instanceof Token.Value;
    }

    private static boolean is(List<Token> expr, int pos, Token.Symbol symbol) {
        return pos >= 0 && pos < expr.size() && expr.get(pos) == symbol;
    }

    // Strip the aws_dbe_b_ prefix if the name carries it, so a query that already names a
    // beacon attribute resolves to the same beacon (RealName).
    private static String realName(String s) {
        return s.length() > BeaconVersion.BEACON_PREFIX.length() && s.startsWith(BeaconVersion.BEACON_PREFIX)
            ? s.substring(BeaconVersion.BEACON_PREFIX.length())
            : s;
    }
}
