package aws.cryptography.dbesdk.testserver.server.handler;

import java.util.LinkedHashMap;
import java.util.Map;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.AuthenticateAction;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.StructuredDataTerminal;

/**
 * Maps the minimal wire structured-data shapes onto the DBE Structured
 * Encryption model types and back: {@code StructuredDataMap} (name → terminal),
 * {@code CryptoSchemaMap} (name → Crypto Action), and {@code AuthenticateSchemaMap}
 * (name → Authenticate Action). A terminal carries opaque {@code value} bytes and
 * a 2-byte {@code typeId}, both passed through unchanged.
 */
public final class StructuredDataCodec {

    /** Wire structured-data map → DBE structured-data map. */
    public Map<String, StructuredDataTerminal> toDbe(
            Map<String, aws.cryptography.dbesdk.testserver.server.model.StructuredDataTerminal> wire) {
        Map<String, StructuredDataTerminal> out = new LinkedHashMap<>();
        wire.forEach((name, terminal) -> out.put(name, StructuredDataTerminal.builder()
            .value(terminal.getValue())
            .typeId(terminal.getTypeId())
            .build()));
        return out;
    }

    /** DBE structured-data map → wire structured-data map. */
    public Map<String, aws.cryptography.dbesdk.testserver.server.model.StructuredDataTerminal> toWire(
            Map<String, StructuredDataTerminal> dbe) {
        Map<String, aws.cryptography.dbesdk.testserver.server.model.StructuredDataTerminal> out =
            new LinkedHashMap<>();
        dbe.forEach((name, terminal) -> out.put(name,
            aws.cryptography.dbesdk.testserver.server.model.StructuredDataTerminal.builder()
                .value(terminal.value())
                .typeId(terminal.typeId())
                .build()));
        return out;
    }

    /** Wire Crypto Schema → DBE Crypto Schema. */
    public Map<String, CryptoAction> toDbeCryptoSchema(
            Map<String, aws.cryptography.dbesdk.testserver.server.model.CryptoAction> wire) {
        Map<String, CryptoAction> out = new LinkedHashMap<>();
        wire.forEach((name, action) -> out.put(name, CryptoAction.valueOf(action.getValue())));
        return out;
    }

    /** Wire Authenticate Schema → DBE Authenticate Schema. */
    public Map<String, AuthenticateAction> toDbeAuthenticateSchema(
            Map<String, aws.cryptography.dbesdk.testserver.server.model.AuthenticateAction> wire) {
        Map<String, AuthenticateAction> out = new LinkedHashMap<>();
        wire.forEach((name, action) -> out.put(name, AuthenticateAction.valueOf(action.getValue())));
        return out;
    }
}
