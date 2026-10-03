package software.amazon.cryptography.dbesdk.structuredencryption.crypto;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.cryptography.dbesdk.structuredencryption.StructuredEncryptionException;
import software.amazon.cryptography.dbesdk.structuredencryption.crypto.FieldKeyDerivation.FieldKey;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Terminal;

/**
 * Encrypts and decrypts a single terminal value with AES-256-GCM
 * (StructuredEncryption behavior spec §4.4). The canonical path is the AAD, so
 * a value can only be decrypted at the same path it was encrypted at.
 *
 * <p>An encrypted terminal's value is {@code originalTypeId(2) ++ ciphertext ++
 * authTag(16)} and its type id is the reserved {@code 0xFFFF}; decryption
 * recovers the original type id from those leading two bytes.
 */
public final class TerminalCryptor {

    private static final byte[] BYTES_TYPE_ID = {(byte) 0xFF, (byte) 0xFF};
    private static final int TYPE_ID_LENGTH = 2;
    private static final int AUTH_TAG_LENGTH = 16;
    private static final int GCM_TAG_BITS = AUTH_TAG_LENGTH * 8;

    private TerminalCryptor() {}

    public static Terminal encrypt(FieldKey fieldKey, byte[] canonicalPathAad, Terminal plaintext) {
        byte[] cipherTextAndTag;
        try {
            cipherTextAndTag = gcm(
                Cipher.ENCRYPT_MODE, fieldKey, canonicalPathAad,
                plaintext.value(), 0, plaintext.value().length);
        } catch (GeneralSecurityException failed) {
            throw new IllegalStateException("AES-GCM field encryption failed", failed);
        }
        byte[] typeId = plaintext.typeId();
        byte[] value = new byte[typeId.length + cipherTextAndTag.length];
        System.arraycopy(typeId, 0, value, 0, typeId.length);
        System.arraycopy(cipherTextAndTag, 0, value, typeId.length, cipherTextAndTag.length);
        return new Terminal(value, BYTES_TYPE_ID.clone());
    }

    public static Terminal decrypt(FieldKey fieldKey, byte[] canonicalPathAad, Terminal encrypted) {
        byte[] value = encrypted.value();
        if (value.length < TYPE_ID_LENGTH + AUTH_TAG_LENGTH) {
            throw new StructuredEncryptionException("cipherTxt too short.");
        }
        byte[] plaintext;
        try {
            plaintext = gcm(
                Cipher.DECRYPT_MODE, fieldKey, canonicalPathAad,
                value, TYPE_ID_LENGTH, value.length - TYPE_ID_LENGTH);
        } catch (AEADBadTagException authFailure) {
            throw new StructuredEncryptionException(
                "Terminal value failed authenticated decryption.", authFailure);
        } catch (GeneralSecurityException failed) {
            throw new IllegalStateException("AES-GCM field decryption failed", failed);
        }
        return new Terminal(plaintext, Arrays.copyOfRange(value, 0, TYPE_ID_LENGTH));
    }

    private static byte[] gcm(
            int mode, FieldKey fieldKey, byte[] aad, byte[] input, int offset, int length)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
            mode,
            new SecretKeySpec(fieldKey.cipherKey(), "AES"),
            new GCMParameterSpec(GCM_TAG_BITS, fieldKey.nonce()));
        cipher.updateAAD(aad);
        return cipher.doFinal(input, offset, length);
    }
}
