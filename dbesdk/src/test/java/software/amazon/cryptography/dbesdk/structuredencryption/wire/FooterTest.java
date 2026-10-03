package software.amazon.cryptography.dbesdk.structuredencryption.wire;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.dbesdk.structuredencryption.StructuredEncryptionException;
import software.amazon.cryptography.dbesdk.structuredencryption.crypto.CanonicalPath;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CanonicalField;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Path;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Terminal;

class FooterTest {

    private static final String HMAC_SHA384 = "HmacSHA384";
    private static final byte[] ENCRYPTED = {0x45, 0x4e, 0x43, 0x52, 0x59, 0x50, 0x54, 0x45, 0x44};
    private static final byte[] PLAINTEXT = {0x50, 0x4c, 0x41, 0x49, 0x4e, 0x54, 0x45, 0x58, 0x54};
    private static final byte[] CANON_PATH = CanonicalPath.canonicalPath("t", Path.ofAttribute("a"));

    @Test
    void canonicalEncryptedFieldLayout() {
        // value = 2-byte original type id ++ 3 bytes of ciphertext+tag stand-in.
        Terminal encrypted = new Terminal(new byte[] {0, 1, 10, 11, 12}, new byte[] {(byte) 0xFF, (byte) 0xFF});

        byte[] expected = concat(
            CANON_PATH,
            new byte[] {0, 0, 0, 0, 0, 0, 0, 3}, // value length - 2
            ENCRYPTED,
            new byte[] {0, 1, 10, 11, 12});

        assertArrayEquals(expected,
            Footer.canonicalField(new CanonicalField(CANON_PATH, Path.ofAttribute("a"), encrypted, CryptoAction.ENCRYPT_AND_SIGN)));
    }

    @Test
    void canonicalPlaintextFieldLayout() {
        Terminal plaintext = new Terminal(new byte[] {5, 6, 7}, new byte[] {0, 1});

        byte[] expected = concat(
            CANON_PATH,
            new byte[] {0, 0, 0, 0, 0, 0, 0, 3}, // value length
            PLAINTEXT,
            new byte[] {0, 1},                   // type id
            new byte[] {5, 6, 7});

        assertArrayEquals(expected,
            Footer.canonicalField(new CanonicalField(CANON_PATH, Path.ofAttribute("a"), plaintext, CryptoAction.SIGN_ONLY)));
    }

    @Test
    void canonicalRecordConcatenatesHeaderAadAndSignedFieldsSkippingDoNothing() {
        byte[] header = {1, 2};
        Map<String, byte[]> encryptionContext = Map.of("k", new byte[] {0x76}); // "v"
        CanonicalField signed = new CanonicalField(CANON_PATH, Path.ofAttribute("a"), new Terminal(new byte[] {5, 6, 7}, new byte[] {0, 1}), CryptoAction.SIGN_ONLY);
        CanonicalField skipped = new CanonicalField(CANON_PATH, Path.ofAttribute("a"), new Terminal(new byte[] {9}, new byte[] {0, 1}), CryptoAction.DO_NOTHING);

        byte[] aad = {0, 1, 0, 1, 0x6b, 0, 1, 0x76}; // count 1, key "k", value "v"
        byte[] expected = concat(
            header,
            new byte[] {0, 0, 0, 0, 0, 0, 0, (byte) aad.length},
            aad,
            concat(CANON_PATH, new byte[] {0, 0, 0, 0, 0, 0, 0, 3}, PLAINTEXT, new byte[] {0, 1}, new byte[] {5, 6, 7}));

        assertArrayEquals(expected,
            Footer.canonicalRecord(header, encryptionContext, List.of(signed, skipped)));
    }

    @Test
    void signProduces103ByteSignatureThatVerifies() throws Exception {
        KeyPair keyPair = p384KeyPair();
        byte[] canonicalHash = filled((byte) 0x2a, 48);

        byte[] signature = Footer.sign(keyPair.getPrivate(), canonicalHash);

        assertEquals(103, signature.length);
        assertTrue(Footer.verifySignature(keyPair.getPublic(), canonicalHash, signature));
        assertFalse(Footer.verifySignature(keyPair.getPublic(), filled((byte) 0x2b, 48), signature));
    }

    @Test
    void validateAcceptsMatchingTagAndRejectsWrongKey() {
        byte[] canonicalHash = filled((byte) 0x2a, 48);
        byte[] signingKey = filled((byte) 0x01, 32);
        byte[] tag = Footer.recipientTag(HMAC_SHA384, signingKey, canonicalHash);
        Footer.Parsed footer = new Footer.Parsed(List.of(tag), Optional.empty());

        Footer.validate(footer, canonicalHash, 1, HMAC_SHA384, signingKey, false, null);

        byte[] wrongKey = filled((byte) 0x02, 32);
        StructuredEncryptionException thrown = assertThrows(
            StructuredEncryptionException.class,
            () -> Footer.validate(footer, canonicalHash, 1, HMAC_SHA384, wrongKey, false, null));
        assertEquals(
            "Signature of record does not match the signature computed when the record was encrypted.",
            thrown.getMessage());
    }

    @Test
    void validateRejectsSignaturePresenceMismatch() {
        byte[] canonicalHash = filled((byte) 0x2a, 48);
        byte[] signingKey = filled((byte) 0x01, 32);
        Footer.Parsed unsignedFooter = new Footer.Parsed(
            List.of(Footer.recipientTag(HMAC_SHA384, signingKey, canonicalHash)), Optional.empty());

        StructuredEncryptionException thrown = assertThrows(
            StructuredEncryptionException.class,
            () -> Footer.validate(unsignedFooter, canonicalHash, 1, HMAC_SHA384, signingKey, true, null));
        assertEquals("Internal error. Signature both does and does not exist.", thrown.getMessage());
    }

    @Test
    void signedFooterRoundTripsThroughTerminal() throws Exception {
        KeyPair keyPair = p384KeyPair();
        byte[] canonicalHash = filled((byte) 0x2a, 48);
        byte[] signingKey = filled((byte) 0x01, 32);
        byte[] tag = Footer.recipientTag(HMAC_SHA384, signingKey, canonicalHash);
        byte[] signature = Footer.sign(keyPair.getPrivate(), canonicalHash);

        Terminal terminal = Footer.makeTerminal(List.of(tag), Optional.of(signature));
        assertArrayEquals(new byte[] {(byte) 0xFF, (byte) 0xFF}, terminal.typeId());
        assertEquals(48 + 103, terminal.value().length);

        Footer.Parsed parsed = Footer.deserialize(terminal.value(), true);
        assertEquals(1, parsed.recipientTags().size());
        assertArrayEquals(tag, parsed.recipientTags().get(0));
        assertArrayEquals(signature, parsed.signature().orElseThrow());

        PublicKey verificationKey = keyPair.getPublic();
        Footer.validate(parsed, canonicalHash, 1, HMAC_SHA384, signingKey, true, verificationKey);
    }

    @Test
    void deserializeRejectsStrangeSignedSize() {
        byte[] strange = new byte[48 + 103 + 5];
        StructuredEncryptionException thrown = assertThrows(
            StructuredEncryptionException.class,
            () -> Footer.deserialize(strange, true));
        assertEquals("Mangled signed footer has strange size", thrown.getMessage());
    }

    private static KeyPair p384KeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        return generator.generateKeyPair();
    }

    private static byte[] filled(byte value, int length) {
        byte[] out = new byte[length];
        Arrays.fill(out, value);
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }
}
