package software.amazon.cryptography.dbesdk.structuredencryption;

import java.util.Map;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.ParsedHeader;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Terminal;

/**
 * The output of a map operation: the resulting structured-data map (encrypted or
 * decrypted), the {@code cryptoSchema} recovered by splitting the result, and the
 * {@link ParsedHeader}. The schema maps each authenticated field to its Crypto
 * Action — every field except DO_NOTHING ones — so a decrypt caller learns the
 * action each field was actually processed under (behavior spec §1).
 */
public record MapStructureOutput(
    Map<String, Terminal> structure,
    Map<String, CryptoAction> cryptoSchema,
    ParsedHeader parsedHeader) {}
