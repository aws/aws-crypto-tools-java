package aws.cryptography.dbesdk.testserver.server.handler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.fail;

import aws.cryptography.dbesdk.testserver.server.error.OperationWrapper;
import aws.cryptography.dbesdk.testserver.server.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.server.model.EncryptItemInput;
import aws.cryptography.dbesdk.testserver.server.model.GenericServerError;
import aws.cryptography.dbesdk.testserver.server.registry.ClientRegistry;
import java.util.Map;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Assume;
import net.jqwik.api.ForAll;
import net.jqwik.api.GenerationMode;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

/**
 * Property-based test for the ClientId guard on non-CreateClient operations,
 * using jqwik. Runs a minimum of 100 generated iterations.
 */
class ClientIdGuardPropertyTest {

    private enum Op { ENCRYPT, DECRYPT }

    // Feature: dbesdk-test-server, Property 5: Missing or unknown ClientId is rejected without side effects
    @Property(tries = 200, generation = GenerationMode.RANDOMIZED)
    void missingOrUnknownClientIdIsRejectedWithoutSideEffects(
            @ForAll("ops") Op op,
            @ForAll("unknownIds") String unknownId) {
        ClientRegistry registry = new ClientRegistry();
        OperationWrapper wrapper = new OperationWrapper();
        ClientIdGuard guard = new ClientIdGuard(registry);
        DdbItemCodec itemCodec = new DdbItemCodec();

        // A canary client that must never be touched by an unknown-id request.
        ControllableDbesdkClient canary = ControllableDbesdkClient.succeeding();
        String canaryId = registry.register(canary);
        // The generated id must be absent/empty/unknown, i.e. not the canary's id.
        Assume.that(!canaryId.equals(unknownId));
        int sizeBefore = registry.size();

        Throwable thrown = runExpectingThrow(op, guard, wrapper, itemCodec, unknownId);

        // (3.9, P5) absent/empty/unknown ClientId -> GenericServerError.
        assertInstanceOf(GenericServerError.class, thrown,
            "a missing or unknown ClientId must yield a GenericServerError");
        // No DBE operation is performed ...
        assertEquals(0, canary.cryptoCalls(),
            "no DBE operation must run for a missing or unknown ClientId");
        // ... and the registry is left unchanged.
        assertEquals(sizeBefore, registry.size(),
            "a rejected request must leave the registry unchanged");
    }

    private static Throwable runExpectingThrow(Op op, ClientIdGuard guard,
                                               OperationWrapper wrapper, DdbItemCodec itemCodec, String id) {
        Map<String, AttributeValue> item = Map.of("k", AttributeValue.fromS("v"));
        try {
            switch (op) {
                case ENCRYPT -> new EncryptItemHandler(guard, wrapper, itemCodec).encryptItem(
                    EncryptItemInput.builder().clientId(id).plaintextItem(itemCodec.toModel(item)).build(),
                    null);
                case DECRYPT -> new DecryptItemHandler(guard, wrapper, itemCodec).decryptItem(
                    DecryptItemInput.builder().clientId(id).encryptedItem(itemCodec.toModel(item)).build(),
                    null);
                default -> fail("unhandled op");
            }
        } catch (Throwable t) {
            return t;
        }
        throw new AssertionError("expected the operation to throw a GenericServerError");
    }

    @Provide
    Arbitrary<Op> ops() {
        return Arbitraries.of(Op.class);
    }

    @Provide
    Arbitrary<String> unknownIds() {
        // Absent manifests as the empty string (the generated required member is
        // error-corrected to ""); also exercise arbitrary and UUID-like unknowns.
        Arbitrary<String> arbitrary = Arbitraries.strings().ofMaxLength(40);
        Arbitrary<String> empty = Arbitraries.just("");
        return Arbitraries.oneOf(empty, arbitrary);
    }
}
