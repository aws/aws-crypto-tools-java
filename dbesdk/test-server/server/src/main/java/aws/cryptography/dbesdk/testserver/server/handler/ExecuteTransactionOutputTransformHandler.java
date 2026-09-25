package aws.cryptography.dbesdk.testserver.server.handler;

import aws.cryptography.dbesdk.testserver.server.error.OperationWrapper;
import aws.cryptography.dbesdk.testserver.server.model.ExecuteTransactionInput;
import aws.cryptography.dbesdk.testserver.server.model.ExecuteTransactionOutput;
import aws.cryptography.dbesdk.testserver.server.model.ExecuteTransactionOutputTransformInput;
import aws.cryptography.dbesdk.testserver.server.model.ExecuteTransactionOutputTransformOutput;
import aws.cryptography.dbesdk.testserver.server.model.ItemResponse;
import aws.cryptography.dbesdk.testserver.server.model.ParameterizedStatement;
import aws.cryptography.dbesdk.testserver.server.registry.TransformsClient;
import aws.cryptography.dbesdk.testserver.server.service.ExecuteTransactionOutputTransformOperation;
import java.util.ArrayList;
import java.util.List;
import software.amazon.awssdk.services.dynamodb.model.ExecuteTransactionRequest;
import software.amazon.awssdk.services.dynamodb.model.ExecuteTransactionResponse;
import software.amazon.smithy.java.server.RequestContext;

/**
 * Resolves the transforms {@code ClientId}, maps the minimal wire
 * {@code ExecuteTransactionOutput} / {@code ExecuteTransactionInput} onto real
 * AWS SDK {@link ExecuteTransactionResponse} / {@link ExecuteTransactionRequest},
 * runs the DBE transact-PartiQL decrypt-after transform, and maps every
 * decrypted item response back.
 */
public final class ExecuteTransactionOutputTransformHandler
        implements ExecuteTransactionOutputTransformOperation {

    private final TransformsClientGuard guard;
    private final OperationWrapper wrapper;
    private final DdbItemCodec itemCodec;

    public ExecuteTransactionOutputTransformHandler(
            TransformsClientGuard guard, OperationWrapper wrapper, DdbItemCodec itemCodec) {
        this.guard = guard;
        this.wrapper = wrapper;
        this.itemCodec = itemCodec;
    }

    @Override
    public ExecuteTransactionOutputTransformOutput executeTransactionOutputTransform(
            ExecuteTransactionOutputTransformInput input, RequestContext context) {
        return wrapper.invoke("ExecuteTransactionOutputTransform", () -> {
            TransformsClient client = guard.resolve(input.getClientId());
            ExecuteTransactionInput wireInput = input.getOriginalInput();
            ExecuteTransactionOutput wireOutput = input.getSdkOutput();

            List<software.amazon.awssdk.services.dynamodb.model.ParameterizedStatement> sdkStatements =
                new ArrayList<>(wireInput.getTransactStatements().size());
            for (ParameterizedStatement statement : wireInput.getTransactStatements()) {
                sdkStatements.add(
                    software.amazon.awssdk.services.dynamodb.model.ParameterizedStatement.builder()
                        .statement(statement.getStatement())
                        .build());
            }
            ExecuteTransactionRequest originalInput = ExecuteTransactionRequest.builder()
                .transactStatements(sdkStatements)
                .build();

            ExecuteTransactionResponse.Builder sdkOutput = ExecuteTransactionResponse.builder();
            if (wireOutput.hasResponses()) {
                sdkOutput.responses(toSdkResponses(wireOutput.getResponses()));
            }

            ExecuteTransactionResponse transformed =
                client.executeTransactionOutputTransform(originalInput, sdkOutput.build());

            ExecuteTransactionOutput.Builder result = ExecuteTransactionOutput.builder();
            if (transformed.hasResponses()) {
                result.responses(toWireResponses(transformed.responses()));
            }
            return ExecuteTransactionOutputTransformOutput.builder()
                .transformedOutput(result.build())
                .build();
        });
    }

    private List<software.amazon.awssdk.services.dynamodb.model.ItemResponse> toSdkResponses(
            List<ItemResponse> wire) {
        List<software.amazon.awssdk.services.dynamodb.model.ItemResponse> out =
            new ArrayList<>(wire.size());
        for (ItemResponse response : wire) {
            software.amazon.awssdk.services.dynamodb.model.ItemResponse.Builder builder =
                software.amazon.awssdk.services.dynamodb.model.ItemResponse.builder();
            if (response.hasItem()) {
                builder.item(itemCodec.toDdb(response.getItem()));
            }
            out.add(builder.build());
        }
        return out;
    }

    private List<ItemResponse> toWireResponses(
            List<software.amazon.awssdk.services.dynamodb.model.ItemResponse> sdk) {
        List<ItemResponse> out = new ArrayList<>(sdk.size());
        for (software.amazon.awssdk.services.dynamodb.model.ItemResponse response : sdk) {
            ItemResponse.Builder builder = ItemResponse.builder();
            if (response.hasItem()) {
                builder.item(itemCodec.toModel(response.item()));
            }
            out.add(builder.build());
        }
        return out;
    }
}
