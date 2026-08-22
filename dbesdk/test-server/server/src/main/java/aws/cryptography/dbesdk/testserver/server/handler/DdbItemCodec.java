package aws.cryptography.dbesdk.testserver.server.handler;

import aws.cryptography.dbesdk.testserver.server.model.AttributeValue;
import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.Map;
import software.amazon.awssdk.core.SdkBytes;

/**
 * Bridges the two {@code AttributeValue} shapes the test server sees:
 *
 * <ul>
 *   <li>The Smithy-modeled {@link AttributeValue} the wire carries (tagged
 *       union via optional members: S / N / B / BOOL / NULL).</li>
 *   <li>The AWS SDK v2 {@link software.amazon.awssdk.services.dynamodb.model.AttributeValue}
 *       DBE's {@code DynamoDbItemEncryptor} consumes and returns.</li>
 * </ul>
 *
 * <p>MVP scope: the five scalars only. Lists, maps, and typed sets (SS/NS/BS)
 * are a mechanical extension — leaving them out keeps the codec small until
 * a test needs them.
 */
public final class DdbItemCodec {

    /** Modeled item map → SDK v2 item map. */
    public Map<String, software.amazon.awssdk.services.dynamodb.model.AttributeValue>
    toDdb(Map<String, AttributeValue> modeled) {
        Map<String, software.amazon.awssdk.services.dynamodb.model.AttributeValue> out =
            new LinkedHashMap<>(modeled.size());
        for (Map.Entry<String, AttributeValue> e : modeled.entrySet()) {
            out.put(e.getKey(), toDdbAttribute(e.getKey(), e.getValue()));
        }
        return out;
    }

    /** SDK v2 item map → modeled item map. */
    public Map<String, AttributeValue> toModel(
            Map<String, software.amazon.awssdk.services.dynamodb.model.AttributeValue> ddb) {
        Map<String, AttributeValue> out = new LinkedHashMap<>(ddb.size());
        for (Map.Entry<String, software.amazon.awssdk.services.dynamodb.model.AttributeValue> e
                : ddb.entrySet()) {
            out.put(e.getKey(), toModelAttribute(e.getKey(), e.getValue()));
        }
        return out;
    }

    // ------------------------------------------------------------------

    private static software.amazon.awssdk.services.dynamodb.model.AttributeValue
    toDdbAttribute(String name, AttributeValue av) {
        // Exactly one variant is expected to be set. If none are, that's a
        // caller bug — surface it rather than emit an empty AttributeValue.
        if (av.getS() != null) {
            return software.amazon.awssdk.services.dynamodb.model.AttributeValue.builder()
                .s(av.getS())
                .build();
        }
        if (av.getN() != null) {
            return software.amazon.awssdk.services.dynamodb.model.AttributeValue.builder()
                .n(av.getN())
                .build();
        }
        if (av.getB() != null) {
            ByteBuffer buf = av.getB();
            byte[] copy = new byte[buf.remaining()];
            buf.duplicate().get(copy);
            return software.amazon.awssdk.services.dynamodb.model.AttributeValue.builder()
                .b(SdkBytes.fromByteArray(copy))
                .build();
        }
        if (av.isBool() != null) {
            return software.amazon.awssdk.services.dynamodb.model.AttributeValue.builder()
                .bool(av.isBool())
                .build();
        }
        if (av.isNull() != null) {
            return software.amazon.awssdk.services.dynamodb.model.AttributeValue.builder()
                .nul(av.isNull())
                .build();
        }
        throw new IllegalArgumentException(
            "Attribute '" + name + "' has no variant member set "
                + "(expected one of S, N, B, BOOL, NULL)");
    }

    private static AttributeValue toModelAttribute(
            String name,
            software.amazon.awssdk.services.dynamodb.model.AttributeValue ddb) {
        if (ddb.s() != null) {
            return AttributeValue.builder().s(ddb.s()).build();
        }
        if (ddb.n() != null) {
            return AttributeValue.builder().n(ddb.n()).build();
        }
        if (ddb.b() != null) {
            return AttributeValue.builder().b(ByteBuffer.wrap(ddb.b().asByteArray())).build();
        }
        if (ddb.bool() != null) {
            return AttributeValue.builder().bool(ddb.bool()).build();
        }
        if (ddb.nul() != null) {
            return AttributeValue.builder().nullMember(ddb.nul()).build();
        }
        throw new IllegalStateException(
            "DBE returned attribute '" + name + "' with an unsupported kind "
                + "(this MVP supports S, N, B, BOOL, NULL)");
    }
}
