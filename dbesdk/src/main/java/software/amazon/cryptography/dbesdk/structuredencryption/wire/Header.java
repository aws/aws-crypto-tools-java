package software.amazon.cryptography.dbesdk.structuredencryption.wire;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.cryptography.dbesdk.structuredencryption.StructuredEncryptionException;
import software.amazon.cryptography.dbesdk.structuredencryption.crypto.ConstantTime;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.EncryptedDataKey;

/**
 * Serializes and parses the structured-encryption header, and computes and
 * verifies its commitment (StructuredEncryption behavior spec §4.5).
 *
 * <p>The full header is the partial header followed by a 32-byte commitment,
 * the first 32 bytes of an HMAC (SHA-384 for both DB-ESDK suites) over the
 * partial header keyed by the Commit Key. The caller supplies the flavor byte,
 * version, legend, and commit inputs; this class owns only the byte layout.
 * Commitment verification is constant-time.
 */
public final class Header {

    private static final int MESSAGE_ID_LENGTH = 32;
    private static final int COMMITMENT_LENGTH = 32;
    private static final int PREFIX_LENGTH = 1 + 1 + MESSAGE_ID_LENGTH;

    static final byte ENCRYPT_AND_SIGN_LEGEND = 0x65;
    static final byte SIGN_AND_INCLUDE_LEGEND = 0x63;
    static final byte SIGN_ONLY_LEGEND = 0x73;

    private Header() {}

    public static byte[] serialize(PartialHeader header) {
        return new ByteWriter()
            .writeByte(header.version())
            .writeByte(header.flavor())
            .writeBytes(header.messageId())
            .writeBytes(serializeLegend(header.legend()))
            .writeBytes(serializeContext(header.encryptionContext()))
            .writeBytes(serializeDataKeys(header.dataKeys()))
            .toByteArray();
    }

    public static byte[] serializeWithCommitment(
            PartialHeader header, byte[] commitKey, String hmacAlgorithm) {
        byte[] body = serialize(header);
        return new ByteWriter()
            .writeBytes(body)
            .writeBytes(commitment(commitKey, body, hmacAlgorithm))
            .toByteArray();
    }

    public static byte[] commitment(byte[] commitKey, byte[] partialHeader, String hmacAlgorithm) {
        try {
            Mac mac = Mac.getInstance(hmacAlgorithm);
            mac.init(new SecretKeySpec(commitKey, hmacAlgorithm));
            byte[] full = mac.doFinal(partialHeader);
            if (full.length < COMMITMENT_LENGTH) {
                throw new StructuredEncryptionException("HMAC did not produce enough bits");
            }
            return Arrays.copyOfRange(full, 0, COMMITMENT_LENGTH);
        } catch (GeneralSecurityException unavailable) {
            throw new IllegalStateException(
                "Header commitment HMAC unavailable for " + hmacAlgorithm, unavailable);
        }
    }

    public static void verifyCommitment(byte[] commitKey, byte[] fullHeader, String hmacAlgorithm) {
        if (fullHeader.length <= COMMITMENT_LENGTH) {
            throw new StructuredEncryptionException("Serialized header too short");
        }
        int bodyLength = fullHeader.length - COMMITMENT_LENGTH;
        byte[] stored = Arrays.copyOfRange(fullHeader, bodyLength, fullHeader.length);
        byte[] calculated = commitment(
            commitKey, Arrays.copyOfRange(fullHeader, 0, bodyLength), hmacAlgorithm);
        if (!ConstantTime.equals(stored, calculated)) {
            throw new StructuredEncryptionException("Key commitment mismatch.");
        }
    }

    public static PartialHeader deserialize(byte[] fullHeader) {
        if (fullHeader.length < PREFIX_LENGTH) {
            throw new StructuredEncryptionException("Serialized PartialHeader too short.");
        }
        ByteReader reader = new ByteReader(fullHeader);
        int version = reader.readByte();
        if (version != 1 && version != 2) {
            throw new StructuredEncryptionException("Invalid Version Number");
        }
        int flavor = reader.readByte();
        if (flavor != 0 && flavor != 1) {
            throw new StructuredEncryptionException("Invalid Flavor");
        }
        byte[] messageId = reader.readBytes(MESSAGE_ID_LENGTH);
        byte[] legend = readLegend(reader);
        Map<String, byte[]> encryptionContext = readContext(reader);
        List<EncryptedDataKey> dataKeys = readDataKeys(reader);
        if (reader.remaining() < COMMITMENT_LENGTH) {
            throw new StructuredEncryptionException(
                "Invalid header serialization: unexpected end of data.");
        }
        if (reader.remaining() > COMMITMENT_LENGTH) {
            throw new StructuredEncryptionException("Invalid header serialization: unexpected bytes.");
        }
        return new PartialHeader(version, (byte) flavor, messageId, legend, encryptionContext, dataKeys);
    }

    private static byte[] serializeLegend(byte[] legend) {
        return new ByteWriter().writeUint16(legend.length).writeBytes(legend).toByteArray();
    }

    // Encryption context is serialized with entries in ascending order of the
    // keys' UTF-8 bytes (behavior spec §4.5) — not Java string order, which
    // differs for multi-byte keys.
    static byte[] serializeContext(Map<String, byte[]> encryptionContext) {
        List<Map.Entry<String, byte[]>> entries = new ArrayList<>(encryptionContext.entrySet());
        entries.sort(Comparator.comparing(
            entry -> entry.getKey().getBytes(StandardCharsets.UTF_8), Arrays::compareUnsigned));

        ByteWriter writer = new ByteWriter().writeUint16(entries.size());
        for (Map.Entry<String, byte[]> entry : entries) {
            byte[] key = entry.getKey().getBytes(StandardCharsets.UTF_8);
            byte[] value = entry.getValue();
            writer.writeUint16(key.length).writeBytes(key).writeUint16(value.length).writeBytes(value);
        }
        return writer.toByteArray();
    }

    private static byte[] serializeDataKeys(List<EncryptedDataKey> dataKeys) {
        ByteWriter writer = new ByteWriter().writeByte(dataKeys.size());
        for (EncryptedDataKey key : dataKeys) {
            writer
                .writeUint16(key.keyProviderId().length).writeBytes(key.keyProviderId())
                .writeUint16(key.keyProviderInfo().length).writeBytes(key.keyProviderInfo())
                .writeUint16(key.ciphertext().length).writeBytes(key.ciphertext());
        }
        return writer.toByteArray();
    }

    private static byte[] readLegend(ByteReader reader) {
        byte[] legend = reader.readBytes(reader.readUint16());
        for (byte b : legend) {
            if (b != ENCRYPT_AND_SIGN_LEGEND && b != SIGN_AND_INCLUDE_LEGEND && b != SIGN_ONLY_LEGEND) {
                throw new StructuredEncryptionException("Invalid byte in stored legend");
            }
        }
        return legend;
    }

    // Reads `count` key-value pairs, requiring keys strictly ascending by their
    // raw bytes — this both enforces the sort and rejects duplicates.
    static Map<String, byte[]> readContext(ByteReader reader) {
        int count = reader.readUint16();
        Map<String, byte[]> context = new LinkedHashMap<>();
        byte[] previousKey = new byte[0];
        for (int i = 0; i < count; i++) {
            byte[] key = reader.readBytes(reader.readUint16());
            byte[] value = reader.readBytes(reader.readUint16());
            if (Arrays.compareUnsigned(previousKey, key) >= 0) {
                throw new StructuredEncryptionException("Context keys out of order.");
            }
            context.put(new String(key, StandardCharsets.UTF_8), value);
            previousKey = key;
        }
        return context;
    }

    private static List<EncryptedDataKey> readDataKeys(ByteReader reader) {
        int count = reader.readByte();
        if (count == 0) {
            throw new StructuredEncryptionException("At least one Data Key required");
        }
        List<EncryptedDataKey> dataKeys = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            byte[] providerId = reader.readBytes(reader.readUint16());
            byte[] providerInfo = reader.readBytes(reader.readUint16());
            byte[] ciphertext = reader.readBytes(reader.readUint16());
            dataKeys.add(new EncryptedDataKey(providerId, providerInfo, ciphertext));
        }
        return dataKeys;
    }
}
