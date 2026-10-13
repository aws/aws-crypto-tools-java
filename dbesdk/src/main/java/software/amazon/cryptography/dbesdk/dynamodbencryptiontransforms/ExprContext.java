package software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms;

import java.util.Map;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

/**
 * The rewritable pieces of a Query/Scan request (FilterExpr.dfy {@code ExprContext}): the
 * key-condition and filter expressions plus the expression attribute names and values they
 * reference. Any field may be {@code null} (the Dafny {@code Option} absence). The beacon
 * rewrite ({@link QueryBeaconizer#beaconize}) consumes one and returns a new one with the
 * expressions and values rewritten to beacon form.
 *
 * @param keyExpr    the key-condition expression, or {@code null}
 * @param filterExpr the filter expression, or {@code null}
 * @param values     {@code ExpressionAttributeValues}, or {@code null}
 * @param names      {@code ExpressionAttributeNames} ({@code #name} aliases), or {@code null}
 */
public record ExprContext(
    String keyExpr,
    String filterExpr,
    Map<String, AttributeValue> values,
    Map<String, String> names) {
}
