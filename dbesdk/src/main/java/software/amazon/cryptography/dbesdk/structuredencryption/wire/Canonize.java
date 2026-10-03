package software.amazon.cryptography.dbesdk.structuredencryption.wire;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import software.amazon.cryptography.dbesdk.structuredencryption.StructuredEncryptionException;
import software.amazon.cryptography.dbesdk.structuredencryption.crypto.CanonicalPath;
import software.amazon.cryptography.dbesdk.structuredencryption.crypto.CanonicalPathComparator;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthItem;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthenticateAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CanonicalAuthField;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CanonicalField;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoItem;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Path;

/**
 * Canonicalization and legend resolution (StructuredEncryption behavior spec
 * §4.2, §4.7). Both directions assign each field its canonical path and sort by
 * those bytes; decrypt then re-derives each field's crypto action from the
 * stored header legend, walked over the signed fields in canonical order.
 */
public final class Canonize {

    private static final Comparator<byte[]> BY_CANONICAL_PATH = new CanonicalPathComparator();

    private Canonize() {}

    public static List<CanonicalField> forEncrypt(String tableName, List<CryptoItem> fields) {
        for (CryptoItem field : fields) {
            requireValidPath(field.key());
        }
        List<CanonicalField> canonical = new ArrayList<>(fields.size());
        for (CryptoItem field : fields) {
            canonical.add(new CanonicalField(
                CanonicalPath.canonicalPath(tableName, field.key()),
                field.key(), field.data(), field.action()));
        }
        canonical.sort(Comparator.comparing(CanonicalField::canonicalPath, BY_CANONICAL_PATH));
        return canonical;
    }

    public static List<CanonicalField> forDecrypt(String tableName, List<AuthItem> fields, byte[] legend) {
        for (AuthItem field : fields) {
            requireValidPath(field.key());
        }
        List<CanonicalAuthField> canonical = new ArrayList<>(fields.size());
        for (AuthItem field : fields) {
            canonical.add(new CanonicalAuthField(
                CanonicalPath.canonicalPath(tableName, field.key()),
                field.key(), field.data(), field.action()));
        }
        canonical.sort(Comparator.comparing(CanonicalAuthField::canonicalPath, BY_CANONICAL_PATH));
        return resolveLegend(canonical, legend);
    }

    // A DO_NOT_SIGN field becomes DO_NOTHING and consumes no legend byte; each
    // SIGN field consumes the next legend byte. A count mismatch either way means
    // the schema no longer matches what was stored.
    static List<CanonicalField> resolveLegend(List<CanonicalAuthField> sorted, byte[] legend) {
        List<CanonicalField> resolved = new ArrayList<>(sorted.size());
        int legendPos = 0;
        for (CanonicalAuthField field : sorted) {
            CryptoAction action;
            if (field.action() == AuthenticateAction.DO_NOT_SIGN) {
                action = CryptoAction.DO_NOTHING;
            } else {
                if (legendPos >= legend.length) {
                    throw new StructuredEncryptionException(
                        "Schema changed : something that was unsigned is now signed.");
                }
                action = legendToAction(legend[legendPos]);
                legendPos++;
            }
            resolved.add(new CanonicalField(field.canonicalPath(), field.originalKey(), field.data(), action));
        }
        if (legendPos != legend.length) {
            throw new StructuredEncryptionException(
                "Schema changed : something that was signed is now unsigned.");
        }
        return resolved;
    }

    static CryptoAction legendToAction(byte legendByte) {
        if (legendByte == Header.ENCRYPT_AND_SIGN_LEGEND) {
            return CryptoAction.ENCRYPT_AND_SIGN;
        }
        if (legendByte == Header.SIGN_AND_INCLUDE_LEGEND) {
            return CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT;
        }
        return CryptoAction.SIGN_ONLY;
    }

    public static List<CryptoItem> unCanon(List<CanonicalField> fields) {
        List<CryptoItem> result = new ArrayList<>(fields.size());
        for (CanonicalField field : fields) {
            result.add(new CryptoItem(field.originalKey(), field.data(), field.action()));
        }
        return result;
    }

    // The inverse of legend resolution: one e/c/s byte per signed field, in
    // canonical order, none for DO_NOTHING (behavior spec §4.5).
    public static byte[] makeLegend(List<CanonicalField> sortedFields) {
        ByteArrayOutputStream legend = new ByteArrayOutputStream();
        for (CanonicalField field : sortedFields) {
            if (field.action() != CryptoAction.DO_NOTHING) {
                legend.write(actionToLegend(field.action()));
            }
        }
        return legend.toByteArray();
    }

    private static byte actionToLegend(CryptoAction action) {
        return switch (action) {
            case ENCRYPT_AND_SIGN -> Header.ENCRYPT_AND_SIGN_LEGEND;
            case SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT -> Header.SIGN_AND_INCLUDE_LEGEND;
            case SIGN_ONLY -> Header.SIGN_ONLY_LEGEND;
            case DO_NOTHING -> throw new IllegalStateException("DO_NOTHING has no legend byte");
        };
    }

    private static void requireValidPath(Path path) {
        for (String segment : path.segments()) {
            if (!StandardCharsets.UTF_8.newEncoder().canEncode(segment)) {
                throw new StructuredEncryptionException("Invalid Paths");
            }
        }
    }
}
