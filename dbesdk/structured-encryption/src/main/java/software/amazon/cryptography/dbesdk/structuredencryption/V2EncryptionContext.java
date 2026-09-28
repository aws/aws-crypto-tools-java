package software.amazon.cryptography.dbesdk.structuredencryption;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoItem;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Terminal;

/**
 * Builds the version-2 encryption-context entries a record's
 * SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT fields contribute (behavior spec §4.8).
 * For each such field it adds an {@code aws-crypto-attr.<dotted-path>} entry
 * whose value is the field's type-specific string encoding, plus a single
 * {@code aws-crypto-legend} entry — one character per attribute, in the order
 * the attribute keys sort by their UTF-8 bytes — recording each attribute's
 * original type so a reader can reverse the encoding.
 *
 * <p>This is upstream of {@code StructuredEncryptionClient}: the caller merges
 * these entries into the encryption context and marks their keys required (so a
 * Required-Encryption-Context CMM keeps them out of the stored header but in the
 * signature AAD) before resolving materials. On decrypt the same entries are
 * rebuilt from the record's plaintext fields, so both sides bind the identical
 * context.
 */
public final class V2EncryptionContext {

    private static final String ATTR_PREFIX = "aws-crypto-attr.";
    private static final String LEGEND_KEY = "aws-crypto-legend";

    private static final byte LEGEND_STRING = 'S';
    private static final byte LEGEND_NUMBER = 'N';
    private static final byte LEGEND_LITERAL = 'L';
    private static final byte LEGEND_BINARY = 'B';

    private static final byte[] TYPE_NULL = {0x00, 0x00};
    private static final byte[] TYPE_STRING = {0x00, 0x01};
    private static final byte[] TYPE_NUMBER = {0x00, 0x02};
    private static final byte[] TYPE_BOOLEAN = {0x00, 0x04};

    private static final byte[] NULL_VALUE = "null".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] TRUE_VALUE = "true".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] FALSE_VALUE = "false".getBytes(StandardCharsets.US_ASCII);

    private V2EncryptionContext() {}

    /**
     * @param fields the whole record; non-SIGN_AND_INCLUDE fields are ignored
     * @return the entries to add to the encryption context, keyed by their EC
     *     names; empty when the record has no SIGN_AND_INCLUDE field
     * @throws StructuredEncryptionException if two paths produce the same EC key
     */
    public static Map<String, byte[]> build(List<CryptoItem> fields) {
        List<CryptoItem> included = new ArrayList<>();
        for (CryptoItem field : fields) {
            if (field.action() == CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT) {
                included.add(field);
            }
        }
        if (included.isEmpty()) {
            return Map.of();
        }

        Map<String, Terminal> byKey = new LinkedHashMap<>();
        for (CryptoItem field : included) {
            String key = ATTR_PREFIX + String.join(".", field.key().segments());
            if (byKey.put(key, field.data()) != null) {
                throw new StructuredEncryptionException(key + " appears twice in encryption context.");
            }
        }

        List<String> sortedKeys = new ArrayList<>(byKey.keySet());
        sortedKeys.sort((left, right) -> Arrays.compareUnsigned(
            left.getBytes(StandardCharsets.UTF_8), right.getBytes(StandardCharsets.UTF_8)));

        Map<String, byte[]> context = new LinkedHashMap<>();
        StringBuilder legend = new StringBuilder(sortedKeys.size());
        for (String key : sortedKeys) {
            Terminal terminal = byKey.get(key);
            legend.append((char) legendChar(terminal));
            context.put(key, contextValue(terminal));
        }
        context.put(LEGEND_KEY, legend.toString().getBytes(StandardCharsets.US_ASCII));
        return context;
    }

    private static byte legendChar(Terminal terminal) {
        byte[] typeId = terminal.typeId();
        if (Arrays.equals(typeId, TYPE_NULL) || Arrays.equals(typeId, TYPE_BOOLEAN)) {
            return LEGEND_LITERAL;
        }
        if (Arrays.equals(typeId, TYPE_STRING)) {
            return LEGEND_STRING;
        }
        if (Arrays.equals(typeId, TYPE_NUMBER)) {
            return LEGEND_NUMBER;
        }
        return LEGEND_BINARY;
    }

    private static byte[] contextValue(Terminal terminal) {
        byte[] typeId = terminal.typeId();
        if (Arrays.equals(typeId, TYPE_NULL)) {
            return NULL_VALUE;
        }
        if (Arrays.equals(typeId, TYPE_STRING)) {
            requireUtf8(terminal.value(), "string");
            return terminal.value();
        }
        if (Arrays.equals(typeId, TYPE_NUMBER)) {
            requireUtf8(terminal.value(), "number");
            return terminal.value();
        }
        if (Arrays.equals(typeId, TYPE_BOOLEAN)) {
            if (terminal.value().length != 1) {
                throw new StructuredEncryptionException("Internal Error : boolean was not of length 1.");
            }
            return terminal.value()[0] == 0 ? FALSE_VALUE : TRUE_VALUE;
        }
        return encodeTerminal(typeId, terminal.value());
    }

    // Base Context Value Version 1: UTF8(Base64(typeId ++ value)).
    private static byte[] encodeTerminal(byte[] typeId, byte[] value) {
        byte[] serialized = new byte[typeId.length + value.length];
        System.arraycopy(typeId, 0, serialized, 0, typeId.length);
        System.arraycopy(value, 0, serialized, typeId.length, value.length);
        return Base64.getEncoder().encode(serialized);
    }

    private static void requireUtf8(byte[] value, String what) {
        try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(value));
        } catch (CharacterCodingException e) {
            throw new StructuredEncryptionException("Internal Error : " + what + " was not UTF8.");
        }
    }
}
