package aws.cryptography.dbesdk.testserver.server.handler;

import aws.cryptography.dbesdk.testserver.server.error.OperationWrapper;
import aws.cryptography.dbesdk.testserver.server.model.BatchExecuteStatementInput;
import aws.cryptography.dbesdk.testserver.server.model.BatchExecuteStatementOutput;
import aws.cryptography.dbesdk.testserver.server.model.BatchExecuteStatementOutputTransformInput;
import aws.cryptography.dbesdk.testserver.server.model.BatchExecuteStatementOutputTransformOutput;
import aws.cryptography.dbesdk.testserver.server.model.BatchStatementRequest;
import aws.cryptography.dbesdk.testserver.server.model.BatchStatementResponse;
import aws.cryptography.dbesdk.testserver.server.registry.TransformsClient;
import aws.cryptography.dbesdk.testserver.server.service.BatchExecuteStatementOutputTransformOperation;
import java.util.ArrayList;
import java.util.List;
import software.amazon.smithy.java.server.RequestContext;

/**
 * Resolves the transforms {@code ClientId}, maps the minimal wire
 * {@code BatchExecuteStatementInput} / {@code BatchExecuteStatementOutput} onto
 * a real AWS SDK {@link software.amazon.awssdk.services.dynamodb.model.BatchExecuteStatementRequest}
 * / {@link software.amazon.awssdk.services.dynamodb.model.BatchExecuteStatementResponse},
 * runs the DBE decrypt-after transform, and maps every decrypted item back.
 */
public final class BatchExecuteStatementOutputTransformHandler
        implements BatchExecuteStatementOutputTransformOperation {

    private final TransformsClientGuard guard;
    private final OperationWrapper wrapper;
    private final DdbItemCodec itemCodec;

    public BatchExecuteStatementOutputTransformHandler(
            TransformsClientGuard guard, OperationWrapper wrapper, DdbItemCodec itemCodec) {
        this.guard = guard;
        this.wrapper = wrapper;
        this.itemCodec = itemCodec;
    }

    @Override
    public BatchExecuteStatementOutputTransformOutput batchExecuteStatementOutputTransform(
            BatchExecuteStatementOutputTransformInput input, RequestContext context) {
        return wrapper.invoke("BatchExecuteStatementOutputTransform", () -> {
            TransformsClient client = guard.resolve(input.getClientId());
            BatchExecuteStatementInput wireInput = input.getOriginalInput();
            BatchExecuteStatementOutput wireOutput = input.getSdkOutput();

            List<software.amazon.awssdk.services.dynamodb.model.BatchStatementRequest> sdkStatements =
                new ArrayList<>(wireInput.getStatements().size());
            for (BatchStatementRequest statement : wireInput.getStatements()) {
                sdkStatements.add(
                    software.amazon.awssdk.services.dynamodb.model.BatchStatementRequest.builder()
                        .statement(statement.getStatement())
                        .build());
            }
            software.amazon.awssdk.services.dynamodb.model.BatchExecuteStatementRequest originalInput =
                software.amazon.awssdk.services.dynamodb.model.BatchExecuteStatementRequest.builder()
                    .statements(sdkStatements)
                    .build();

            software.amazon.awssdk.services.dynamodb.model.BatchExecuteStatementResponse.Builder sdkOutput =
                software.amazon.awssdk.services.dynamodb.model.BatchExecuteStatementResponse.builder();
            if (wireOutput.getResponses() != null) {
                sdkOutput.responses(toSdkResponses(wireOutput.getResponses()));
            }

            software.amazon.awssdk.services.dynamodb.model.BatchExecuteStatementResponse transformed =
                client.batchExecuteStatementOutputTransform(originalInput, sdkOutput.build());

            BatchExecuteStatementOutput.Builder result = BatchExecuteStatementOutput.builder();
            if (transformed.hasResponses()) {
                result.responses(toWireResponses(transformed.responses()));
            }
            return BatchExecuteStatementOutputTransformOutput.builder()
                .transformedOutput(result.build())
                .build();
        });
    }

    private List<software.amazon.awssdk.services.dynamodb.model.BatchStatementResponse> toSdkResponses(
            List<BatchStatementResponse> wire) {
        List<software.amazon.awssdk.services.dynamodb.model.BatchStatementResponse> out =
            new ArrayList<>(wire.size());
        for (BatchStatementResponse response : wire) {
            software.amazon.awssdk.services.dynamodb.model.BatchStatementResponse.Builder builder =
                software.amazon.awssdk.services.dynamodb.model.BatchStatementResponse.builder()
                    .tableName(response.getTableName());
            if (response.getItem() != null) {
                builder.item(itemCodec.toDdb(response.getItem()));
            }
            out.add(builder.build());
        }
        return out;
    }

    private List<BatchStatementResponse> toWireResponses(
            List<software.amazon.awssdk.services.dynamodb.model.BatchStatementResponse> sdk) {
        List<BatchStatementResponse> out = new ArrayList<>(sdk.size());
        for (software.amazon.awssdk.services.dynamodb.model.BatchStatementResponse response : sdk) {
            BatchStatementResponse.Builder builder = BatchStatementResponse.builder();
            if (response.tableName() != null) {
                builder.tableName(response.tableName());
            }
            if (response.hasItem()) {
                builder.item(itemCodec.toModel(response.item()));
            }
            out.add(builder.build());
        }
        return out;
    }
}
