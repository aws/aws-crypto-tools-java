package aws.cryptography.dbesdk.testserver.server.handler;

import aws.cryptography.dbesdk.testserver.server.error.OperationWrapper;
import aws.cryptography.dbesdk.testserver.server.model.DeleteItemInput;
import aws.cryptography.dbesdk.testserver.server.model.DeleteItemOutput;
import aws.cryptography.dbesdk.testserver.server.model.DeleteItemOutputTransformInput;
import aws.cryptography.dbesdk.testserver.server.model.DeleteItemOutputTransformOutput;
import aws.cryptography.dbesdk.testserver.server.registry.TransformsClient;
import aws.cryptography.dbesdk.testserver.server.service.DeleteItemOutputTransformOperation;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemResponse;
import software.amazon.smithy.java.server.RequestContext;

/**
 * Resolves the transforms {@code ClientId}, maps the minimal wire
 * {@code DeleteItemOutput} / {@code DeleteItemInput} onto real AWS SDK
 * {@link DeleteItemResponse} / {@link DeleteItemRequest}, runs the DBE
 * DeleteItem decrypt-after transform (restoring the deleted item's plaintext
 * when {@code ReturnValues} requested it), and maps the transformed response
 * back to the wire shape.
 */
public final class DeleteItemOutputTransformHandler
        implements DeleteItemOutputTransformOperation {

    private final TransformsClientGuard guard;
    private final OperationWrapper wrapper;
    private final DdbItemCodec itemCodec;

    public DeleteItemOutputTransformHandler(
            TransformsClientGuard guard, OperationWrapper wrapper, DdbItemCodec itemCodec) {
        this.guard = guard;
        this.wrapper = wrapper;
        this.itemCodec = itemCodec;
    }

    @Override
    public DeleteItemOutputTransformOutput deleteItemOutputTransform(
            DeleteItemOutputTransformInput input, RequestContext context) {
        return wrapper.invoke("DeleteItemOutputTransform", () -> {
            TransformsClient client = guard.resolve(input.getClientId());
            DeleteItemInput wire = input.getOriginalInput();
            DeleteItemOutput wireOutput = input.getSdkOutput();

            DeleteItemRequest.Builder sdk = DeleteItemRequest.builder()
                .tableName(wire.getTableName())
                .key(itemCodec.toDdb(wire.getKey()));
            if (wire.getConditionExpression() != null) {
                sdk.conditionExpression(wire.getConditionExpression());
            }
            if (wire.getExpressionAttributeNames() != null
                    && !wire.getExpressionAttributeNames().isEmpty()) {
                sdk.expressionAttributeNames(wire.getExpressionAttributeNames());
            }
            if (wire.getExpressionAttributeValues() != null
                    && !wire.getExpressionAttributeValues().isEmpty()) {
                sdk.expressionAttributeValues(itemCodec.toDdb(wire.getExpressionAttributeValues()));
            }
            DeleteItemRequest originalInput = sdk.build();

            DeleteItemResponse.Builder sdkOutput = DeleteItemResponse.builder();
            if (wireOutput.hasAttributes()) {
                sdkOutput.attributes(itemCodec.toDdb(wireOutput.getAttributes()));
            }

            DeleteItemResponse transformed =
                client.deleteItemOutputTransform(originalInput, sdkOutput.build());

            DeleteItemOutput.Builder result = DeleteItemOutput.builder();
            if (transformed.hasAttributes() && !transformed.attributes().isEmpty()) {
                result.attributes(itemCodec.toModel(transformed.attributes()));
            }
            return DeleteItemOutputTransformOutput.builder()
                .transformedOutput(result.build())
                .build();
        });
    }
}
