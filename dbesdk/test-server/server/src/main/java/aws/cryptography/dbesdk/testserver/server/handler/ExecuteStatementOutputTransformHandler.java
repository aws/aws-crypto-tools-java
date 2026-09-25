package aws.cryptography.dbesdk.testserver.server.handler;

import aws.cryptography.dbesdk.testserver.server.error.OperationWrapper;
import aws.cryptography.dbesdk.testserver.server.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.server.model.ExecuteStatementInput;
import aws.cryptography.dbesdk.testserver.server.model.ExecuteStatementOutput;
import aws.cryptography.dbesdk.testserver.server.model.ExecuteStatementOutputTransformInput;
import aws.cryptography.dbesdk.testserver.server.model.ExecuteStatementOutputTransformOutput;
import aws.cryptography.dbesdk.testserver.server.registry.TransformsClient;
import aws.cryptography.dbesdk.testserver.server.service.ExecuteStatementOutputTransformOperation;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.model.ExecuteStatementRequest;
import software.amazon.awssdk.services.dynamodb.model.ExecuteStatementResponse;
import software.amazon.smithy.java.server.RequestContext;

/**
 * Resolves the transforms {@code ClientId}, maps the minimal wire
 * {@code ExecuteStatementOutput} / {@code ExecuteStatementInput} onto real AWS
 * SDK {@link ExecuteStatementResponse} / {@link ExecuteStatementRequest}, runs
 * the DBE PartiQL decrypt-after transform, and maps every decrypted item back.
 */
public final class ExecuteStatementOutputTransformHandler
        implements ExecuteStatementOutputTransformOperation {

    private final TransformsClientGuard guard;
    private final OperationWrapper wrapper;
    private final DdbItemCodec itemCodec;

    public ExecuteStatementOutputTransformHandler(
            TransformsClientGuard guard, OperationWrapper wrapper, DdbItemCodec itemCodec) {
        this.guard = guard;
        this.wrapper = wrapper;
        this.itemCodec = itemCodec;
    }

    @Override
    public ExecuteStatementOutputTransformOutput executeStatementOutputTransform(
            ExecuteStatementOutputTransformInput input, RequestContext context) {
        return wrapper.invoke("ExecuteStatementOutputTransform", () -> {
            TransformsClient client = guard.resolve(input.getClientId());
            ExecuteStatementInput wireInput = input.getOriginalInput();
            ExecuteStatementOutput wireOutput = input.getSdkOutput();

            ExecuteStatementRequest originalInput = ExecuteStatementRequest.builder()
                .statement(wireInput.getStatement())
                .build();

            ExecuteStatementResponse.Builder sdkOutput = ExecuteStatementResponse.builder();
            if (wireOutput.hasItems()) {
                sdkOutput.items(toSdkItems(wireOutput.getItems()));
            }

            ExecuteStatementResponse transformed =
                client.executeStatementOutputTransform(originalInput, sdkOutput.build());

            ExecuteStatementOutput.Builder result = ExecuteStatementOutput.builder();
            if (transformed.hasItems()) {
                result.items(toWireItems(transformed.items()));
            }
            return ExecuteStatementOutputTransformOutput.builder()
                .transformedOutput(result.build())
                .build();
        });
    }

    private List<Map<String, software.amazon.awssdk.services.dynamodb.model.AttributeValue>> toSdkItems(
            List<Map<String, AttributeValue>> wire) {
        List<Map<String, software.amazon.awssdk.services.dynamodb.model.AttributeValue>> out =
            new ArrayList<>(wire.size());
        for (Map<String, AttributeValue> item : wire) {
            out.add(itemCodec.toDdb(item));
        }
        return out;
    }

    private List<Map<String, AttributeValue>> toWireItems(
            List<Map<String, software.amazon.awssdk.services.dynamodb.model.AttributeValue>> sdk) {
        List<Map<String, AttributeValue>> out = new ArrayList<>(sdk.size());
        for (Map<String, software.amazon.awssdk.services.dynamodb.model.AttributeValue> item : sdk) {
            out.add(itemCodec.toModel(item));
        }
        return out;
    }
}
