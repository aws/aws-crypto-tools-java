package software.amazon.cryptography.dbesdk.structuredencryption.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.dbesdk.structuredencryption.StructuredEncryptionException;
import software.amazon.cryptography.dbesdk.structuredencryption.crypto.FieldKeyDerivation.FieldKey;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Path;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Terminal;

class TerminalCryptorTest {

    private static final FieldKey FIELD_KEY = new FieldKey(sequence(32), sequence(12));
    private static final byte[] AAD = CanonicalPath.canonicalPath("table", Path.ofAttribute("attr"));
    private static final byte[] STRING_TYPE_ID = {0x00, 0x01};

    @Test
    void roundTripRecoversTypeIdAndValue() {
        Terminal plaintext = new Terminal("hello".getBytes(StandardCharsets.UTF_8), STRING_TYPE_ID);

        Terminal decrypted = TerminalCryptor.decrypt(
            FIELD_KEY, AAD, TerminalCryptor.encrypt(FIELD_KEY, AAD, plaintext));

        assertArrayEquals(plaintext.typeId(), decrypted.typeId());
        assertArrayEquals(plaintext.value(), decrypted.value());
    }

    @Test
    void encryptSetsBytesTypeIdAndSerializes() {
        Terminal plaintext = new Terminal("hello".getBytes(StandardCharsets.UTF_8), STRING_TYPE_ID);

        Terminal encrypted = TerminalCryptor.encrypt(FIELD_KEY, AAD, plaintext);

        assertArrayEquals(new byte[] {(byte) 0xFF, (byte) 0xFF}, encrypted.typeId());
        assertArrayEquals(STRING_TYPE_ID, Arrays.copyOfRange(encrypted.value(), 0, 2));
        assertEquals(2 + plaintext.value().length + 16, encrypted.value().length);
    }

    @Test
    void decryptRejectsTooShortValue() {
        Terminal tooShort = new Terminal(new byte[17], new byte[] {(byte) 0xFF, (byte) 0xFF});

        StructuredEncryptionException thrown = assertThrows(
            StructuredEncryptionException.class,
            () -> TerminalCryptor.decrypt(FIELD_KEY, AAD, tooShort));
        assertEquals("cipherTxt too short.", thrown.getMessage());
    }

    @Test
    void decryptRejectsTamperedCiphertext() {
        Terminal encrypted = TerminalCryptor.encrypt(
            FIELD_KEY, AAD, new Terminal("hello".getBytes(StandardCharsets.UTF_8), STRING_TYPE_ID));
        byte[] tampered = encrypted.value().clone();
        tampered[tampered.length - 1] ^= 0x01;

        StructuredEncryptionException thrown = assertThrows(
            StructuredEncryptionException.class,
            () -> TerminalCryptor.decrypt(FIELD_KEY, AAD, new Terminal(tampered, encrypted.typeId())));
        assertInstanceOf(AEADBadTagException.class, thrown.getCause());
    }

    @Test
    void decryptRejectsWrongCanonicalPathAad() {
        Terminal encrypted = TerminalCryptor.encrypt(
            FIELD_KEY, AAD, new Terminal("hello".getBytes(StandardCharsets.UTF_8), STRING_TYPE_ID));
        byte[] wrongAad = CanonicalPath.canonicalPath("table", Path.ofAttribute("other"));

        StructuredEncryptionException thrown = assertThrows(
            StructuredEncryptionException.class,
            () -> TerminalCryptor.decrypt(FIELD_KEY, wrongAad, encrypted));
        assertInstanceOf(AEADBadTagException.class, thrown.getCause());
    }

    private static byte[] sequence(int length) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = (byte) i;
        }
        return out;
    }
}
