package aws.cryptography.dbesdk.testserver.server.handler;

import aws.cryptography.dbesdk.testserver.server.error.OperationWrapper;
import aws.cryptography.dbesdk.testserver.server.model.GetItemInput;
import aws.cryptography.dbesdk.testserver.server.model.GetItemInputTransformInput;
import aws.cryptography.dbesdk.testserver.server.model.GetItemInputTransformOutput;
import aws.cryptography.dbesdk.testserver.server.registry.TransformsClient;
import aws.cryptography.dbesdk.testserver.server.service.GetItemInputTransformOperation;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.smithy.java.server.RequestContext;

/**
 * Resolves the transforms {@code ClientId}, maps the minimal wire
 * {@code GetItemInput} onto a real AWS SDK {@link GetItemRequest}, runs the DBE
 * GetItem beacon-rewrite input transform, and maps the transformed request back
 * to the wire shape.
 */
public final class GetItemInputTransformHandler implements GetItemInputTransformOperation {

    private final TransformsClientGuard guard;
    private final OperationWrapper wrapper;
    private final DdbItemCodec itemCodec;

    public GetItemInputTransformHandler(
            TransformsClientGuard guard, OperationWrapper wrapper, DdbItemCodec itemCodec) {
        this.guard = guard;
        this.wrapper = wrapper;
        this.itemCodec = itemCodec;
    }

    @Override
    public GetItemInputTransformOutput getItemInputTransform(
            GetItemInputTransformInput input, RequestContext context) {
        return wrapper.invoke("GetItemInputTransform", () -> {
            TransformsClient client = guard.resolve(input.getClientId());
            GetItemInput wireInput = input.getSdkInput();

            GetItemRequest sdkInput = GetItemRequest.builder()
                .tableName(wireInput.getTableName())
                .key(itemCodec.toDdb(wireInput.getKey()))
                .build();

            GetItemRequest transformed = client.getItemInputTransform(sdkInput);

            return GetItemInputTransformOutput.builder()
                .transformedInput(GetItemInput.builder()
                    .tableName(transformed.tableName())
                    .key(itemCodec.toModel(transformed.key()))
                    .build())
                .build();
        });
    }
}
