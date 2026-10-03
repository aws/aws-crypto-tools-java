package software.amazon.cryptography.dbesdk.structuredencryption.wire;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.dbesdk.structuredencryption.StructuredEncryptionException;
import software.amazon.cryptography.dbesdk.structuredencryption.crypto.CanonicalPath;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthItem;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthenticateAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CanonicalAuthField;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CanonicalField;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoItem;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Path;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Terminal;

class CanonizeTest {

    private static final byte ENCRYPT = 0x65; // 'e'
    private static final byte SIGN_ONLY = 0x73; // 's'
    private static final Terminal TERMINAL = new Terminal(new byte[] {1}, new byte[] {0, 1});

    @Test
    void forEncryptAssignsCanonicalPathAndSortsLengthMajor() {
        List<CryptoItem> input = List.of(
            crypto("zz", CryptoAction.SIGN_ONLY),
            crypto("aa", CryptoAction.ENCRYPT_AND_SIGN),
            crypto("aaa", CryptoAction.DO_NOTHING));

        List<CanonicalField> result = Canonize.forEncrypt("name", input);

        // Length-major: "aa" and "zz" (2 chars) before "aaa" (3 chars).
        assertEquals(List.of("aa", "zz", "aaa"),
            result.stream().map(field -> field.originalKey().segments().get(0)).toList());
        assertArrayEquals(
            CanonicalPath.canonicalPath("name", Path.ofAttribute("aa")),
            result.get(0).canonicalPath());
        assertEquals(CryptoAction.ENCRYPT_AND_SIGN, result.get(0).action());
    }

    @Test
    void forEncryptRejectsUnencodablePath() {
        List<CryptoItem> input = List.of(
            new CryptoItem(Path.ofAttribute("\ud800"), TERMINAL, CryptoAction.SIGN_ONLY)); // lone surrogate

        StructuredEncryptionException thrown = assertThrows(
            StructuredEncryptionException.class, () -> Canonize.forEncrypt("name", input));
        assertEquals("Invalid Paths", thrown.getMessage());
    }

    @Test
    void resolveLegendMapsSignedFieldsAndSkipsUnsigned() {
        List<CanonicalAuthField> sorted = List.of(
            auth("a", AuthenticateAction.SIGN),
            auth("b", AuthenticateAction.DO_NOT_SIGN),
            auth("c", AuthenticateAction.SIGN));

        List<CanonicalField> resolved = Canonize.resolveLegend(sorted, new byte[] {ENCRYPT, SIGN_ONLY});

        assertEquals(
            List.of(CryptoAction.ENCRYPT_AND_SIGN, CryptoAction.DO_NOTHING, CryptoAction.SIGN_ONLY),
            resolved.stream().map(CanonicalField::action).toList());
    }

    @Test
    void resolveLegendRejectsTooFewLegendBytes() {
        List<CanonicalAuthField> sorted = List.of(
            auth("a", AuthenticateAction.SIGN),
            auth("b", AuthenticateAction.SIGN));

        StructuredEncryptionException thrown = assertThrows(
            StructuredEncryptionException.class,
            () -> Canonize.resolveLegend(sorted, new byte[] {ENCRYPT}));
        assertEquals("Schema changed : something that was unsigned is now signed.", thrown.getMessage());
    }

    @Test
    void resolveLegendRejectsTooManyLegendBytes() {
        List<CanonicalAuthField> sorted = List.of(auth("a", AuthenticateAction.SIGN));

        StructuredEncryptionException thrown = assertThrows(
            StructuredEncryptionException.class,
            () -> Canonize.resolveLegend(sorted, new byte[] {ENCRYPT, SIGN_ONLY}));
        assertEquals("Schema changed : something that was signed is now unsigned.", thrown.getMessage());
    }

    @Test
    void forDecryptCanonicalizesSortsAndResolves() {
        List<AuthItem> input = List.of(
            new AuthItem(Path.ofAttribute("zz"), TERMINAL, AuthenticateAction.SIGN),
            new AuthItem(Path.ofAttribute("aa"), TERMINAL, AuthenticateAction.SIGN));

        // Sorted order is aa, zz; legend bytes apply in that order.
        List<CanonicalField> result = Canonize.forDecrypt("name", input, new byte[] {ENCRYPT, SIGN_ONLY});

        assertEquals(List.of("aa", "zz"),
            result.stream().map(field -> field.originalKey().segments().get(0)).toList());
        assertEquals(
            List.of(CryptoAction.ENCRYPT_AND_SIGN, CryptoAction.SIGN_ONLY),
            result.stream().map(CanonicalField::action).toList());
    }

    @Test
    void unCanonRecoversOriginalKeyDataAndAction() {
        CanonicalField field = new CanonicalField(
            CanonicalPath.canonicalPath("name", Path.ofAttribute("aa")),
            Path.ofAttribute("aa"), TERMINAL, CryptoAction.SIGN_ONLY);

        List<CryptoItem> result = Canonize.unCanon(List.of(field));

        assertEquals(1, result.size());
        assertEquals(List.of("aa"), result.get(0).key().segments());
        assertArrayEquals(TERMINAL.value(), result.get(0).data().value());
        assertEquals(CryptoAction.SIGN_ONLY, result.get(0).action());
    }

    private static CryptoItem crypto(String key, CryptoAction action) {
        return new CryptoItem(Path.ofAttribute(key), TERMINAL, action);
    }

    private static CanonicalAuthField auth(String key, AuthenticateAction action) {
        return new CanonicalAuthField(
            CanonicalPath.canonicalPath("name", Path.ofAttribute(key)),
            Path.ofAttribute(key), TERMINAL, action);
    }
}
