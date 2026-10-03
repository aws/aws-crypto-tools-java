package aws.cryptography.dbesdk.testserver.server.handler;

import aws.cryptography.dbesdk.testserver.server.error.OperationWrapper;
import aws.cryptography.dbesdk.testserver.server.model.UpdateItemInput;
import aws.cryptography.dbesdk.testserver.server.model.UpdateItemOutput;
import aws.cryptography.dbesdk.testserver.server.model.UpdateItemOutputTransformInput;
import aws.cryptography.dbesdk.testserver.server.model.UpdateItemOutputTransformOutput;
import aws.cryptography.dbesdk.testserver.server.registry.TransformsClient;
import aws.cryptography.dbesdk.testserver.server.service.UpdateItemOutputTransformOperation;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemResponse;
import software.amazon.smithy.java.server.RequestContext;

/**
 * Resolves the transforms {@code ClientId}, maps the minimal wire
 * {@code UpdateItemOutput} / {@code UpdateItemInput} onto real AWS SDK
 * {@link UpdateItemResponse} / {@link UpdateItemRequest}, runs the DBE
 * UpdateItem decrypt-after transform (restoring the updated item's plaintext
 * when {@code ReturnValues} requested it), and maps the transformed response
 * back to the wire shape.
 */
public final class UpdateItemOutputTransformHandler
        implements UpdateItemOutputTransformOperation {

    private final TransformsClientGuard guard;
    private final OperationWrapper wrapper;
    private final DdbItemCodec itemCodec;

    public UpdateItemOutputTransformHandler(
            TransformsClientGuard guard, OperationWrapper wrapper, DdbItemCodec itemCodec) {
        this.guard = guard;
        this.wrapper = wrapper;
        this.itemCodec = itemCodec;
    }

    @Override
    public UpdateItemOutputTransformOutput updateItemOutputTransform(
            UpdateItemOutputTransformInput input, RequestContext context) {
        return wrapper.invoke("UpdateItemOutputTransform", () -> {
            TransformsClient client = guard.resolve(input.getClientId());
            UpdateItemInput wire = input.getOriginalInput();
            UpdateItemOutput wireOutput = input.getSdkOutput();

            UpdateItemRequest.Builder sdk = UpdateItemRequest.builder()
                .tableName(wire.getTableName())
                .key(itemCodec.toDdb(wire.getKey()));
            if (wire.getUpdateExpression() != null) {
                sdk.updateExpression(wire.getUpdateExpression());
            }
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
            UpdateItemRequest originalInput = sdk.build();

            UpdateItemResponse.Builder sdkOutput = UpdateItemResponse.builder();
            if (wireOutput.hasAttributes()) {
                sdkOutput.attributes(itemCodec.toDdb(wireOutput.getAttributes()));
            }

            UpdateItemResponse transformed =
                client.updateItemOutputTransform(originalInput, sdkOutput.build());

            UpdateItemOutput.Builder result = UpdateItemOutput.builder();
            if (transformed.hasAttributes() && !transformed.attributes().isEmpty()) {
                result.attributes(itemCodec.toModel(transformed.attributes()));
            }
            return UpdateItemOutputTransformOutput.builder()
                .transformedOutput(result.build())
                .build();
        });
    }
}
