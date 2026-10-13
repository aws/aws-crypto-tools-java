package software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbesdk.dynamodbencryption.BeaconKeySource;
import software.amazon.cryptography.dbesdk.dynamodbencryption.BeaconVersion;
import software.amazon.cryptography.dbesdk.dynamodbencryption.MaybeKeyId;
import software.amazon.cryptography.dbesdk.dynamodbencryption.MaybeKeyMap;

/**
 * A table's searchable-encryption write path: adds the beacon version tag before
 * encryption and the {@code aws_dbe_b_*} encrypted beacons after. Mirrors the
 * Dafny {@code AddSignedBeacons} + {@code GetEncryptedBeacons} on a table's
 * {@code SearchInfo}, composing the already-native {@link BeaconVersion}.
 *
 * <p>The per-beacon HMAC keys come from a {@link BeaconKeySource}: configured directly
 * (literal) or retrieved from a key store and cached. The write partition is 0 (the base
 * case; a configured partition selector is a later slice).
 *
 * <p>Standard and compound beacons (including virtual-field sources) are supported: the
 * fully-signed compound beacons are written by {@link #addSignedBeacons} before encryption,
 * and the standard beacons plus the compound beacons with an encrypted part are written by
 * {@link #encryptedBeacons} after. Multi-tenant writes, whose key id comes from the item,
 * are a separate slice.
 */
public final class SearchInfo {

    /** Written before encryption so a reader can tell which beacon version wrote the item. */
    static final String VERSION_TAG = "aws_dbe_v_1";

    private final BeaconVersion beaconVersion;
    private final BeaconKeySource keySource;

    public SearchInfo(BeaconVersion beaconVersion, BeaconKeySource keySource) {
        this.beaconVersion = beaconVersion;
        this.keySource = keySource;
    }

    /**
     * The signed-beacon names that must be configured SIGN_ONLY on the item encryptor, so the
     * {@code <name>} attributes {@link #addSignedBeacons} writes before encryption are
     * authenticated (transforms Index.dfy {@code AddSignedBeaconActions}).
     */
    public List<String> signedBeaconNames() {
        return beaconVersion.listSignedBeacons();
    }

    /**
     * Rewrite a Query/Scan's key and filter expressions into beacon form (DDBSupport
     * {@code QueryInputForBeacons}/{@code ScanInputForBeacons}, base single-partition case):
     * resolve the beacon keys from the key source and delegate the token rewrite to
     * {@link QueryBeaconizer}. The multi-tenant key id is taken as absent here; extracting it
     * from the query is a later feature.
     */
    public ExprContext beaconizeQuery(ExprContext context) {
        MaybeKeyMap keys = keySource.getKeyMap(new MaybeKeyId.DontUse());
        return QueryBeaconizer.beaconize(beaconVersion, context, keys, 0);
    }

    /**
     * Re-filter decrypted Query/Scan results against the original key and filter expressions
     * (DDBSupport {@code QueryOutputForBeacons}/{@code ScanOutputForBeacons}), removing the
     * false positives a beacon query's superset contains. The {@code context} carries the
     * customer's original (pre-rewrite) expressions. The re-filter recomputes beacons keyless
     * from each item, so no key source is consulted (write partition 0).
     */
    public List<Map<String, AttributeValue>> filterResults(
            ExprContext context, List<Map<String, AttributeValue>> items) {
        return ResultFilter.filterResults(
            beaconVersion, items, context.keyExpr(), context.filterExpr(), context.names(), context.values(), 0);
    }

    /**
     * The signed attributes carried into encryption: the fully-signed compound beacons
     * (each as attribute {@code <name>}, from plaintext part values) plus the version tag
     * (a single space). All are authenticated with the rest of the signed item.
     *
     * @throws DynamoDbEncryptionTransformsException if a signed beacon's name already exists
     *     in the item with a different value (DDBSupport AddSignedBeacons consistency check)
     */
    Map<String, AttributeValue> addSignedBeacons(Map<String, AttributeValue> item) {
        Map<String, AttributeValue> signed = beaconVersion.generateSignedBeacons(item, 0);
        for (Map.Entry<String, AttributeValue> entry : signed.entrySet()) {
            AttributeValue existing = item.get(entry.getKey());
            if (existing != null && !existing.equals(entry.getValue())) {
                throw new DynamoDbEncryptionTransformsException(
                    "Signed beacon " + entry.getKey() + " does not match the supplied attribute value.");
            }
        }
        Map<String, AttributeValue> out = new LinkedHashMap<>(item);
        out.putAll(signed);
        out.put(VERSION_TAG, AttributeValue.fromS(" "));
        return out;
    }

    /** The {@code aws_dbe_b_*} beacon attributes for the item, appended after encryption. */
    Map<String, AttributeValue> encryptedBeacons(Map<String, AttributeValue> item) {
        MaybeKeyMap keys = keySource.getKeyMap(new MaybeKeyId.DontUse());
        if (keys instanceof MaybeKeyMap.Keys resolved) {
            return beaconVersion.generateEncryptedBeacons(item, resolved.keys(), 0);
        }
        // A literal or single-tenant source always yields keys for a no-key-id write; a
        // multi-tenant source needs the item's key id, which is a later write slice.
        throw new DynamoDbEncryptionTransformsException(
            "Multi-tenant beacon writes are not yet supported on the native write path.");
    }
}
