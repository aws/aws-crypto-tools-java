package software.amazon.cryptography.dbesdk.structuredencryption.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Derives per-field encryption keys (StructuredEncryption behavior spec §4.3).
 * Two steps that must reproduce the Dafny bytes exactly:
 *
 * <ol>
 *   <li>The Field Root Key is HKDF of the plaintext data key, with no salt and
 *       info {@code "AWS_DBE_DERIVE_KEY" ++ messageId}, under the suite's KDF hash.
 *   <li>Each field's key is the first 44 bytes of an AES-256-CTR keystream keyed
 *       by the Field Root Key, split into a 32-byte cipher key and a 12-byte
 *       nonce. AES-CTR expands one HKDF output into many field keys cheaply.
 * </ol>
 *
 * <p>The keystream nonce embeds three times the field offset, because each field
 * consumes three AES blocks (44 bytes); the {@code test/Crypt.dfy} golden vectors
 * pin the exact bytes.
 */
public final class FieldKeyDerivation {

    private static final byte[] DERIVE_KEY_LABEL =
        "AWS_DBE_DERIVE_KEY".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] FIELD_KEY_NONCE_PREFIX =
        "AwsDbeField".getBytes(StandardCharsets.US_ASCII);

    private static final int CIPHER_KEY_SIZE = 32;
    private static final int NONCE_SIZE = 12;
    private static final int FIELD_KEY_SIZE = CIPHER_KEY_SIZE + NONCE_SIZE; // 44

    // offset * 3 must fit the nonce's unsigned 32-bit counter (behavior spec §4.3).
    private static final int MAX_OFFSET = 1431655765;

    private FieldKeyDerivation() {}

    /** A field's derived cipher key (32 bytes) and AES-GCM nonce (12 bytes). */
    public record FieldKey(byte[] cipherKey, byte[] nonce) {}

    public static byte[] fieldRootKey(
            String kdfMacAlgorithm, byte[] dataKey, byte[] messageId, int keyLength) {
        return Hkdf.deriveKey(kdfMacAlgorithm, null, dataKey, deriveKeyInfo(messageId), keyLength);
    }

    static byte[] deriveKeyInfo(byte[] messageId) {
        byte[] info = new byte[DERIVE_KEY_LABEL.length + messageId.length];
        System.arraycopy(DERIVE_KEY_LABEL, 0, info, 0, DERIVE_KEY_LABEL.length);
        System.arraycopy(messageId, 0, info, DERIVE_KEY_LABEL.length, messageId.length);
        return info;
    }

    public static FieldKey fieldKey(byte[] fieldRootKey, int offset) {
        if (offset < 0 || offset >= MAX_OFFSET) {
            throw new IllegalArgumentException("Too many encrypted fields.");
        }
        byte[] stream = ctrKeystream(fieldRootKey, fieldKeyNonce((long) offset * 3), FIELD_KEY_SIZE);
        return new FieldKey(
            Arrays.copyOfRange(stream, 0, CIPHER_KEY_SIZE),
            Arrays.copyOfRange(stream, CIPHER_KEY_SIZE, FIELD_KEY_SIZE));
    }

    static byte[] fieldKeyNonce(long counter) {
        byte[] nonce = new byte[16];
        System.arraycopy(FIELD_KEY_NONCE_PREFIX, 0, nonce, 0, FIELD_KEY_NONCE_PREFIX.length);
        nonce[11] = (byte) FIELD_KEY_SIZE; // 0x2c, the eventual FieldKey length
        nonce[12] = (byte) (counter >>> 24);
        nonce[13] = (byte) (counter >>> 16);
        nonce[14] = (byte) (counter >>> 8);
        nonce[15] = (byte) counter;
        return nonce;
    }

    private static byte[] ctrKeystream(byte[] key, byte[] nonce, int length) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(nonce));
            return cipher.doFinal(new byte[length]);
        } catch (GeneralSecurityException failed) {
            throw new IllegalStateException("AES-CTR keystream derivation failed", failed);
        }
    }
}
