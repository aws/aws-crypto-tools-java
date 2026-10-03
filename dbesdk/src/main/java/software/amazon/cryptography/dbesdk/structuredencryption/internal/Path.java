package software.amazon.cryptography.dbesdk.structuredencryption.internal;

import java.util.List;

/**
 * An ordered path to a terminal within a structure. Today only map-member
 * segments are used (flat maps): a top-level DynamoDB attribute is a single
 * segment whose value is the attribute name. Nested-path support is a later
 * additive change — the Dafny source only enables the map-member segment
 * variant (StructuredEncryption behavior spec §1, §5).
 *
 * <p>The segment list order is significant: it drives the canonical-path
 * encoding (behavior spec §4.1), which is both the AES-GCM AAD and the sort key.
 */
public record Path(List<String> segments) {

    public Path {
        segments = List.copyOf(segments);
    }

    /** Convenience for the flat-map case: a single-segment path over one attribute. */
    public static Path ofAttribute(String attributeName) {
        return new Path(List.of(attributeName));
    }
}
