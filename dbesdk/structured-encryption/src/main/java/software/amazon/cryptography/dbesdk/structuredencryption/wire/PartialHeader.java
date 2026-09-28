package software.amazon.cryptography.dbesdk.structuredencryption.wire;

import java.util.List;
import java.util.Map;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.EncryptedDataKey;

/**
 * The header without its trailing commitment (StructuredEncryption behavior
 * spec §4.5): format version, flavor, message id, the encrypt legend, the
 * stored encryption context, and the encrypted data keys.
 *
 * <p>Encryption-context keys are the logical UTF-8 strings; ordering on the
 * wire is by the keys' UTF-8 bytes, not Java string order (see {@link Header}).
 */
public record PartialHeader(
    int version,
    byte flavor,
    byte[] messageId,
    byte[] legend,
    Map<String, byte[]> encryptionContext,
    List<EncryptedDataKey> dataKeys) {}
