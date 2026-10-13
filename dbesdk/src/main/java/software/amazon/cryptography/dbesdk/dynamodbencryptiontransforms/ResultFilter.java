package software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbesdk.dynamodbencryption.BeaconVersion;
import software.amazon.cryptography.dbesdk.dynamodbencryption.MaybeKeyMap;
import software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms.ExpressionTokenizer.Token;

/**
 * The searchable-encryption output filter (DynamoDBFilterExpr {@code FilterResults} /
 * {@code FilterItems}). A beacon query matches on truncated-hash beacons, so DynamoDB returns
 * a superset of the true results; this re-checks each decrypted item against the original
 * key/filter predicate and drops the false positives.
 *
 * <p>The predicate is beaconized under {@link MaybeKeyMap.DontUseKeys}: beacon attributes
 * become {@code aws_dbe_b_<name>} but the compared values are left plaintext. Each item is
 * then augmented with its {@linkplain BeaconVersion#generatePlainBeacons plain beacons} —
 * the same beacons recomputed keyless (plaintext) from the decrypted item — so the beaconized
 * predicate evaluates the original plaintext comparison and the superset collapses to the
 * exact result.
 */
final class ResultFilter {

    private ResultFilter() {
    }

    /**
     * The subset of {@code items} that satisfy the original key and filter expressions
     * (applied in that order). An empty item list, or no key and no filter expression,
     * returns the items unchanged.
     */
    static List<Map<String, AttributeValue>> filterResults(
            BeaconVersion beaconVersion, List<Map<String, AttributeValue>> items,
            String keyExpr, String filterExpr,
            Map<String, String> names, Map<String, AttributeValue> values, int partition) {
        if (items.isEmpty() || (keyExpr == null && filterExpr == null)) {
            return items;
        }
        List<Map<String, AttributeValue>> afterKeys = keyExpr != null
            ? filterItems(beaconVersion, keyExpr, items, names, values, partition)
            : items;
        return filterExpr != null
            ? filterItems(beaconVersion, filterExpr, afterKeys, names, values, partition)
            : afterKeys;
    }

    // Beaconize the expression keyless, then keep each item whose plain-beacon-augmented form
    // satisfies it.
    private static List<Map<String, AttributeValue>> filterItems(
            BeaconVersion beaconVersion, String expression, List<Map<String, AttributeValue>> items,
            Map<String, String> names, Map<String, AttributeValue> values, int partition) {
        QueryBeaconizer.ParsedContext rewritten = QueryBeaconizer.beaconizeParsedExpr(
            beaconVersion,
            ExpressionTokenizer.parse(expression),
            values != null ? values : Map.of(),
            names,
            new MaybeKeyMap.DontUseKeys(),
            Map.of(),
            partition);
        List<Token> rpn = ExpressionEvaluator.convertToRpn(ExpressionEvaluator.convertToPrefix(rewritten.expr()));

        List<Map<String, AttributeValue>> kept = new ArrayList<>(items.size());
        for (Map<String, AttributeValue> item : items) {
            Map<String, AttributeValue> augmented = new LinkedHashMap<>(item);
            augmented.putAll(beaconVersion.generatePlainBeacons(item, partition));
            if (ExpressionEvaluator.evalExpr(rpn, augmented, rewritten.names(), rewritten.values())) {
                kept.add(item);
            }
        }
        return kept;
    }
}
