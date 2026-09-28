package software.amazon.cryptography.dbesdk.structuredencryption.crypto;

import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * RFC 5869 HKDF (extract-then-expand). The DB-ESDK derives the Field Root Key
 * and the Commit Key with this KDF (StructuredEncryption behavior spec §4.3,
 * §4.5). The hash is chosen by the caller via a JCA Mac algorithm name (e.g.
 * {@code HmacSHA384}, {@code HmacSHA512}), matching the algorithm suite.
 *
 * <p>An absent salt means a string of HashLen zero bytes, per RFC 5869 §2.2 —
 * which is what the DB-ESDK always uses (it calls the KDF with no salt).
 */
public final class Hkdf {

    private Hkdf() {}

    public static byte[] deriveKey(
            String macAlgorithm, byte[] salt, byte[] ikm, byte[] info, int length) {
        try {
            Mac mac = Mac.getInstance(macAlgorithm);
            int hashLength = mac.getMacLength();
            if (length < 1 || length > 255 * hashLength) {
                throw new IllegalArgumentException(
                    "HKDF output length must be in [1, 255*HashLen]; got " + length);
            }
            byte[] prk = extract(mac, saltOrZeros(salt, hashLength), ikm);
            return expand(mac, prk, info, length);
        } catch (GeneralSecurityException unavailable) {
            throw new IllegalStateException("HKDF unavailable for " + macAlgorithm, unavailable);
        }
    }

    private static byte[] saltOrZeros(byte[] salt, int hashLength) {
        return (salt == null || salt.length == 0) ? new byte[hashLength] : salt;
    }

    // PRK = HMAC-Hash(salt, IKM)
    private static byte[] extract(Mac mac, byte[] salt, byte[] ikm) throws GeneralSecurityException {
        mac.init(new SecretKeySpec(salt, mac.getAlgorithm()));
        return mac.doFinal(ikm);
    }

    // T(i) = HMAC-Hash(PRK, T(i-1) ++ info ++ i); OKM = first `length` bytes of T(1)..T(n).
    private static byte[] expand(Mac mac, byte[] prk, byte[] info, int length)
            throws GeneralSecurityException {
        mac.init(new SecretKeySpec(prk, mac.getAlgorithm()));
        byte[] okm = new byte[length];
        byte[] previousBlock = new byte[0];
        int filled = 0;
        for (int counter = 1; filled < length; counter++) {
            mac.update(previousBlock);
            mac.update(info);
            mac.update((byte) counter);
            previousBlock = mac.doFinal();
            int take = Math.min(previousBlock.length, length - filled);
            System.arraycopy(previousBlock, 0, okm, filled, take);
            filled += take;
        }
        return okm;
    }
}
