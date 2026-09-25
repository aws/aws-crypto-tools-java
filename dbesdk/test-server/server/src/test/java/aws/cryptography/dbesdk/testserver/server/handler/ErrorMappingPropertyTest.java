package aws.cryptography.dbesdk.testserver.server.handler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.fail;

import aws.cryptography.dbesdk.testserver.server.error.OperationWrapper;
import aws.cryptography.dbesdk.testserver.server.model.DBESDKClientError;
import aws.cryptography.dbesdk.testserver.server.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.server.model.EncryptItemInput;
import aws.cryptography.dbesdk.testserver.server.model.GenericServerError;
import aws.cryptography.dbesdk.testserver.server.registry.ClientRegistry;
import java.util.Map;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.GenerationMode;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

/**
 * Property-based test for error mapping by origin at the handler layer, using
 * jqwik. Runs a minimum of 100 generated iterations.
 */
class ErrorMappingPropertyTest {

    private enum Op { ENCRYPT, DECRYPT }

    // Feature: dbesdk-test-server, Property 8: Errors are mapped by origin
    @Property(tries = 200, generation = GenerationMode.RANDOMIZED)
    void errorsAreMappedByOrigin(@ForAll("ops") Op op,
                                 @ForAll boolean esdkOrigin,
                                 @ForAll("messages") String message) {
        ClientRegistry registry = new ClientRegistry();
        OperationWrapper wrapper = new OperationWrapper();
        ClientIdGuard guard = new ClientIdGuard(registry);

        ControllableEsdkClient client = esdkOrigin
            ? ControllableEsdkClient.failingInsideEsdk(message)
            : ControllableEsdkClient.failingInFramework(message);
        String clientId = registry.register(client);
        int sizeBefore = registry.size();

        Throwable thrown = runExpectingThrow(op, guard, wrapper, clientId);

        if (esdkOrigin) {
            // (5.6, P8) ESDK-origin failure -> DBESDKClientError, message unmodified,
            // never a GenericServerError.
            DBESDKClientError error = assertInstanceOf(DBESDKClientError.class, thrown,
                "an ESDK-origin failure must map to DBESDKClientError");
            assertEquals(message, error.getMessage(),
                "DBESDKClientError message must equal the ESDK exception message, unmodified");
        } else {
            // (5.5, P8) framework-origin failure -> GenericServerError, never an
            // DBESDKClientError.
            assertInstanceOf(GenericServerError.class, thrown,
                "a framework-origin failure must map to GenericServerError");
        }

        // In the failure case no ciphertext/plaintext is returned (an exception
        // was thrown, not an output) and the registry is unchanged.
        assertEquals(sizeBefore, registry.size(),
            "a failed operation must leave the registry unchanged");
    }

    private static Throwable runExpectingThrow(Op op, ClientIdGuard guard,
                                               OperationWrapper wrapper, String clientId) {
        DdbItemCodec itemCodec = new DdbItemCodec();
        Map<String, AttributeValue> item = Map.of("k", AttributeValue.fromS("payload"));
        try {
            switch (op) {
                case ENCRYPT -> new EncryptItemHandler(guard, wrapper, itemCodec).encryptItem(
                    EncryptItemInput.builder()
                        .clientId(clientId)
                        .plaintextItem(itemCodec.toModel(item))
                        .build(),
                    null);
                case DECRYPT -> new DecryptItemHandler(guard, wrapper, itemCodec).decryptItem(
                    DecryptItemInput.builder()
                        .clientId(clientId)
                        .encryptedItem(itemCodec.toModel(item))
                        .build(),
                    null);
                default -> fail("unhandled op");
            }
        } catch (Throwable t) {
            return t;
        }
        throw new AssertionError("expected the operation to throw a modeled error");
    }

    @Provide
    Arbitrary<Op> ops() {
        return Arbitraries.of(Op.class);
    }

    @Provide
    Arbitrary<String> messages() {
        return Arbitraries.strings().ofMinLength(1).ofMaxLength(120);
    }
}
