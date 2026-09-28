package software.amazon.cryptography.dbesdk.structuredencryption;

import java.util.List;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoItem;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.ParsedHeader;

/**
 * The output of a path operation: the resulting Crypto List (encrypted or
 * decrypted, per the operation) and the {@link ParsedHeader} it produced or
 * parsed. The Dafny path outputs carry no crypto schema — that is a map-operation
 * output (see {@link MapStructureOutput}).
 */
public record PathStructureOutput(List<CryptoItem> structure, ParsedHeader parsedHeader) {}
