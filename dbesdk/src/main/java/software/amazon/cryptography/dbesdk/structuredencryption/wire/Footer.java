package software.amazon.cryptography.dbesdk.structuredencryption.wire;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.cryptography.dbesdk.structuredencryption.StructuredEncryptionException;
import software.amazon.cryptography.dbesdk.structuredencryption.crypto.ConstantTime;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CanonicalField;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Terminal;

/**
 * Builds and verifies the footer (StructuredEncryption behavior spec §4.6). The
 * footer terminal value is the recipient tags (one 48-byte HMAC per encrypted
 * data key, in signing-key order) followed by an optional 103-byte ECDSA
 * signature. Both are computed over the canonical hash — SHA-384 of the
 * canonical record (full header, then the encryption context as AAD, then each
 * signed field's canonical form in canonical-path order).
 *
 * <p>The signature is P-384. The DB-ESDK requires it to be exactly 103 bytes;
 * DER-encoded ECDSA signatures vary in length, so signing re-signs until it
 * produces a 103-byte encoding (equivalent to the reference's negate-s trick —
 * both yield a valid 103-byte signature, and ECDSA signing is randomized, so
 * neither is byte-reproducible). Because the caller supplies the canonical hash
 * and the MPL performs its own SHA-384 before signing, {@code SHA384withECDSA}
 * over the canonical hash reproduces the MPL's sign/verify exactly.
 */
public final class Footer {

    static final int RECIPIENT_TAG_SIZE = 48;
    static final int SIGNATURE_SIZE = 103;

    private static final byte[] ENCRYPTED = "ENCRYPTED".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PLAINTEXT = "PLAINTEXT".getBytes(StandardCharsets.US_ASCII);
    private static final int TYPE_ID_LENGTH = 2;
    private static final int MAX_SIGN_ATTEMPTS = 256;

    private Footer() {}

    /** A parsed footer: the recipient tags and, if the suite signs, the signature. */
    public record Parsed(List<byte[]> recipientTags, Optional<byte[]> signature) {}

    public static byte[] canonicalRecord(
            byte[] header, Map<String, byte[]> encryptionContext, List<CanonicalField> fields) {
        byte[] aad = Header.serializeContext(encryptionContext);
        ByteWriter writer = new ByteWriter()
            .writeBytes(header)
            .writeUint64(aad.length)
            .writeBytes(aad);
        for (CanonicalField field : fields) {
            if (field.action() != CryptoAction.DO_NOTHING) {
                writer.writeBytes(canonicalField(field));
            }
        }
        return writer.toByteArray();
    }

    static byte[] canonicalField(CanonicalField field) {
        Terminal data = field.data();
        if (field.action() == CryptoAction.ENCRYPT_AND_SIGN) {
            // The value already begins with the 2-byte original type id, so the
            // recorded length is value length minus those two bytes.
            if (data.value().length < TYPE_ID_LENGTH) {
                throw new StructuredEncryptionException("Bad length.");
            }
            return new ByteWriter()
                .writeBytes(field.canonicalPath())
                .writeUint64(data.value().length - TYPE_ID_LENGTH)
                .writeBytes(ENCRYPTED)
                .writeBytes(data.value())
                .toByteArray();
        }
        return new ByteWriter()
            .writeBytes(field.canonicalPath())
            .writeUint64(data.value().length)
            .writeBytes(PLAINTEXT)
            .writeBytes(data.typeId())
            .writeBytes(data.value())
            .toByteArray();
    }

    public static byte[] canonicalHash(
            byte[] header, Map<String, byte[]> encryptionContext, List<CanonicalField> fields) {
        return sha384(canonicalRecord(header, encryptionContext, fields));
    }

    public static byte[] recipientTag(
            String hmacAlgorithm, byte[] symmetricSigningKey, byte[] canonicalHash) {
        byte[] tag = hmac(hmacAlgorithm, symmetricSigningKey, canonicalHash);
        if (tag.length != RECIPIENT_TAG_SIZE) {
            throw new StructuredEncryptionException("Bad hash length");
        }
        return tag;
    }

    public static byte[] sign(PrivateKey signingKey, byte[] canonicalHash) {
        try {
            Signature signer = Signature.getInstance("SHA384withECDSA");
            signer.initSign(signingKey, new SecureRandom());
            for (int attempt = 0; attempt < MAX_SIGN_ATTEMPTS; attempt++) {
                signer.update(canonicalHash);
                byte[] signature = signer.sign();
                if (signature.length == SIGNATURE_SIZE) {
                    return signature;
                }
            }
            throw new StructuredEncryptionException(
                "Could not produce a " + SIGNATURE_SIZE + "-byte signature.");
        } catch (GeneralSecurityException failed) {
            throw new IllegalStateException("ECDSA P-384 signing failed", failed);
        }
    }

    public static boolean verifySignature(
            PublicKey verificationKey, byte[] canonicalHash, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance("SHA384withECDSA");
            verifier.initVerify(verificationKey);
            verifier.update(canonicalHash);
            return verifier.verify(signature);
        } catch (SignatureException malformedOrWrong) {
            return false;
        } catch (GeneralSecurityException failed) {
            throw new IllegalStateException("ECDSA P-384 verification failed", failed);
        }
    }

    public static Terminal makeTerminal(List<byte[]> recipientTags, Optional<byte[]> signature) {
        ByteWriter writer = new ByteWriter();
        for (byte[] tag : recipientTags) {
            writer.writeBytes(tag);
        }
        signature.ifPresent(writer::writeBytes);
        return new Terminal(writer.toByteArray(), new byte[] {(byte) 0xFF, (byte) 0xFF});
    }

    public static Parsed deserialize(byte[] footerValue, boolean hasSignature) {
        int length = footerValue.length;
        if (hasSignature) {
            if (length < RECIPIENT_TAG_SIZE + SIGNATURE_SIZE) {
                throw new StructuredEncryptionException("Footer too short.");
            }
            if ((length - SIGNATURE_SIZE) % RECIPIENT_TAG_SIZE != 0) {
                throw new StructuredEncryptionException("Mangled signed footer has strange size");
            }
            int tagsLength = length - SIGNATURE_SIZE;
            return new Parsed(
                gatherTags(footerValue, tagsLength),
                Optional.of(Arrays.copyOfRange(footerValue, tagsLength, length)));
        }
        if (length % RECIPIENT_TAG_SIZE != 0) {
            throw new StructuredEncryptionException("Mangled unsigned footer has strange size");
        }
        if (length < RECIPIENT_TAG_SIZE) {
            throw new StructuredEncryptionException("Footer too short.");
        }
        return new Parsed(gatherTags(footerValue, length), Optional.empty());
    }

    public static void validate(
            Parsed footer,
            byte[] canonicalHash,
            int encryptedDataKeyCount,
            String hmacAlgorithm,
            byte[] symmetricSigningKey,
            boolean suiteHasEcdsa,
            PublicKey verificationKey) {
        if (footer.recipientTags().size() != encryptedDataKeyCount) {
            throw new StructuredEncryptionException(
                "There are a different number of recipient tags in the stored header "
                    + "than there are in the decryption materials.");
        }
        byte[] hash = hmac(hmacAlgorithm, symmetricSigningKey, canonicalHash);
        if (hash.length != RECIPIENT_TAG_SIZE) {
            throw new StructuredEncryptionException("Bad hash length");
        }
        boolean matched = false;
        for (byte[] tag : footer.recipientTags()) {
            if (ConstantTime.equals(hash, tag)) {
                matched = true;
                break;
            }
        }
        if (!matched) {
            throw new StructuredEncryptionException(
                "Signature of record does not match the signature computed when the record "
                    + "was encrypted.");
        }
        if (footer.signature().isPresent() != suiteHasEcdsa) {
            throw new StructuredEncryptionException(
                "Internal error. Signature both does and does not exist.");
        }
        if (footer.signature().isPresent()
                && !verifySignature(verificationKey, canonicalHash, footer.signature().get())) {
            throw new StructuredEncryptionException("Signature did not verify");
        }
    }

    private static List<byte[]> gatherTags(byte[] data, int tagsLength) {
        List<byte[]> tags = new ArrayList<>();
        for (int pos = 0; pos < tagsLength; pos += RECIPIENT_TAG_SIZE) {
            tags.add(Arrays.copyOfRange(data, pos, pos + RECIPIENT_TAG_SIZE));
        }
        return tags;
    }

    private static byte[] sha384(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-384").digest(data);
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-384 unavailable", unavailable);
        }
    }

    private static byte[] hmac(String algorithm, byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key, algorithm));
            return mac.doFinal(message);
        } catch (GeneralSecurityException unavailable) {
            throw new IllegalStateException("HMAC unavailable for " + algorithm, unavailable);
        }
    }
}
