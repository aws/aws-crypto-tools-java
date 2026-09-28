package aws.cryptography.dbesdk.testserver.server.registry;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.PathSegment;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.StructureSegment;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.StructuredDataTerminal;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Path;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Terminal;

/**
 * Marshals between the test-server's published DB-ESDK model types (the
 * {@link StructuredClient} interface surface) and the native pipeline's internal
 * types. Pure conversion — no CMM, no crypto — so the MPL touchpoints stay in
 * {@link NativeStructuredClient}.
 *
 * <p>The published {@code CryptoItem}/{@code AuthItem}/{@code CryptoAction}/
 * {@code AuthenticateAction} collide by simple name with their native
 * counterparts, so both are fully qualified here rather than imported.
 */
final class StructuredTypeAdapters {

    private StructuredTypeAdapters() {}

    static List<software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoItem> toNativeItems(
            List<software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoItem> published) {
        List<software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoItem> items =
            new ArrayList<>(published.size());
        for (software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoItem item : published) {
            items.add(new software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoItem(
                toNativePath(item.key()), toNativeTerminal(item.data()), toNativeCryptoAction(item.action())));
        }
        return items;
    }

    static List<software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoItem> toPublishedItems(
            List<software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoItem> native_) {
        List<software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoItem> published =
            new ArrayList<>(native_.size());
        for (software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoItem item : native_) {
            published.add(software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoItem.builder()
                .key(toPublishedPath(item.key()))
                .data(toPublishedTerminal(item.data()))
                .action(toPublishedCryptoAction(item.action()))
                .build());
        }
        return published;
    }

    static List<software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthItem> toNativeAuthItems(
            List<software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.AuthItem> published) {
        List<software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthItem> items =
            new ArrayList<>(published.size());
        for (software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.AuthItem item : published) {
            items.add(new software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthItem(
                toNativePath(item.key()), toNativeTerminal(item.data()), toNativeAuthAction(item.action())));
        }
        return items;
    }

    static Path toNativePath(List<PathSegment> segments) {
        List<String> members = new ArrayList<>(segments.size());
        for (PathSegment segment : segments) {
            members.add(segment.member().key());
        }
        return new Path(members);
    }

    static List<PathSegment> toPublishedPath(Path path) {
        List<PathSegment> segments = new ArrayList<>(path.segments().size());
        for (String member : path.segments()) {
            segments.add(PathSegment.builder()
                .member(StructureSegment.builder().key(member).build())
                .build());
        }
        return segments;
    }

    static Terminal toNativeTerminal(StructuredDataTerminal terminal) {
        return new Terminal(bytes(terminal.value()), bytes(terminal.typeId()));
    }

    static StructuredDataTerminal toPublishedTerminal(Terminal terminal) {
        return StructuredDataTerminal.builder()
            .value(ByteBuffer.wrap(terminal.value()))
            .typeId(ByteBuffer.wrap(terminal.typeId()))
            .build();
    }

    static software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction toNativeCryptoAction(
            software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction action) {
        return switch (action) {
            case ENCRYPT_AND_SIGN ->
                software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction.ENCRYPT_AND_SIGN;
            case SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT ->
                software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction
                    .SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT;
            case SIGN_ONLY ->
                software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction.SIGN_ONLY;
            case DO_NOTHING ->
                software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction.DO_NOTHING;
        };
    }

    static software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction toPublishedCryptoAction(
            software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction action) {
        return switch (action) {
            case ENCRYPT_AND_SIGN ->
                software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction.ENCRYPT_AND_SIGN;
            case SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT ->
                software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction
                    .SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT;
            case SIGN_ONLY ->
                software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction.SIGN_ONLY;
            case DO_NOTHING ->
                software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction.DO_NOTHING;
        };
    }

    static software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthenticateAction toNativeAuthAction(
            software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.AuthenticateAction action) {
        return switch (action) {
            case SIGN ->
                software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthenticateAction.SIGN;
            case DO_NOT_SIGN ->
                software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthenticateAction.DO_NOT_SIGN;
        };
    }

    static Map<String, Terminal> toNativeTerminalMap(Map<String, StructuredDataTerminal> published) {
        Map<String, Terminal> out = new LinkedHashMap<>();
        published.forEach((key, terminal) -> out.put(key, toNativeTerminal(terminal)));
        return out;
    }

    static Map<String, StructuredDataTerminal> toPublishedTerminalMap(Map<String, Terminal> native_) {
        Map<String, StructuredDataTerminal> out = new LinkedHashMap<>();
        native_.forEach((key, terminal) -> out.put(key, toPublishedTerminal(terminal)));
        return out;
    }

    static Map<String, software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction> toNativeSchema(
            Map<String, software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction> published) {
        Map<String, software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction> out =
            new LinkedHashMap<>();
        published.forEach((key, action) -> out.put(key, toNativeCryptoAction(action)));
        return out;
    }

    static Map<String, software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthenticateAction>
            toNativeAuthSchema(
                Map<String, software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.AuthenticateAction>
                    published) {
        Map<String, software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthenticateAction> out =
            new LinkedHashMap<>();
        published.forEach((key, action) -> out.put(key, toNativeAuthAction(action)));
        return out;
    }

    // Native items paired only where a plaintext field also has a Crypto Action, for
    // materials resolution (field count/size and V2 context). Any key mismatch is
    // reported by the native map operation itself, so mismatched keys are skipped here.
    static List<software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoItem> toNativeItemsForMaterials(
            Map<String, StructuredDataTerminal> plaintext,
            Map<String, software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction> schema) {
        List<software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoItem> items = new ArrayList<>();
        plaintext.forEach((key, terminal) -> {
            var action = schema.get(key);
            if (action != null) {
                items.add(new software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoItem(
                    Path.ofAttribute(key), toNativeTerminal(terminal), toNativeCryptoAction(action)));
            }
        });
        return items;
    }

    private static byte[] bytes(ByteBuffer buffer) {
        ByteBuffer duplicate = buffer.duplicate();
        byte[] out = new byte[duplicate.remaining()];
        duplicate.get(out);
        return out;
    }
}
