package software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbesdk.dynamodbencryption.BeaconVersion;
import software.amazon.cryptography.dbesdk.dynamodbencryption.StandardBeacon;

class ResultFilterTest {

    private static BeaconVersion colorBeacon() {
        return BeaconVersion.of(List.of(StandardBeacon.create("color", 10, "color", false, 0)));
    }

    @Test
    void removesFalsePositivesFromTheBeaconSuperset() {
        // A beacon query matches on truncated hashes, so DynamoDB can return items whose
        // plaintext does not match. The output filter re-checks the plaintext and drops them.
        BeaconVersion version = colorBeacon();
        Map<String, AttributeValue> red = Map.of("id", AttributeValue.fromS("1"), "color", AttributeValue.fromS("red"));
        Map<String, AttributeValue> blue = Map.of("id", AttributeValue.fromS("2"), "color", AttributeValue.fromS("blue"));

        List<Map<String, AttributeValue>> kept = ResultFilter.filterResults(
            version, List.of(red, blue), null, "color = :c", null, Map.of(":c", AttributeValue.fromS("red")), 0);

        assertEquals(List.of(red), kept);
    }

    @Test
    void recomputedPlainBeaconOverlaysAnyStoredBeaconAttribute() {
        // A decrypted item still carries its stored (keyed) aws_dbe_b_color. The filter must
        // recompute the keyless plain beacon from the plaintext and let it win, so the match
        // reflects the plaintext — not whatever hash happens to be stored.
        BeaconVersion version = colorBeacon();
        Map<String, AttributeValue> stored = Map.of(
            "id", AttributeValue.fromS("1"),
            "color", AttributeValue.fromS("red"),
            "aws_dbe_b_color", AttributeValue.fromS("a-stale-stored-hash"));

        List<Map<String, AttributeValue>> kept = ResultFilter.filterResults(
            version, List.of(stored), null, "color = :c", null, Map.of(":c", AttributeValue.fromS("red")), 0);

        assertEquals(List.of(stored), kept);
    }

    @Test
    void noExpressionReturnsItemsUnchanged() {
        BeaconVersion version = colorBeacon();
        Map<String, AttributeValue> item = Map.of("color", AttributeValue.fromS("red"));
        List<Map<String, AttributeValue>> items = List.of(item);
        assertTrue(ResultFilter.filterResults(version, items, null, null, null, null, 0) == items);
    }
}
