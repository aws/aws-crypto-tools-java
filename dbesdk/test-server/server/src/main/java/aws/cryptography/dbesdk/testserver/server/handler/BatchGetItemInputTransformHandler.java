package aws.cryptography.dbesdk.testserver.server.handler;

import aws.cryptography.dbesdk.testserver.server.error.OperationWrapper;
import aws.cryptography.dbesdk.testserver.server.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.server.model.BatchGetItemInput;
import aws.cryptography.dbesdk.testserver.server.model.BatchGetItemInputTransformInput;
import aws.cryptography.dbesdk.testserver.server.model.BatchGetItemInputTransformOutput;
import aws.cryptography.dbesdk.testserver.server.model.KeysAndAttributes;
import aws.cryptography.dbesdk.testserver.server.registry.TransformsClient;
import aws.cryptography.dbesdk.testserver.server.service.BatchGetItemInputTransformOperation;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest;
import software.amazon.smithy.java.server.RequestContext;

/**
 * Resolves the transforms {@code ClientId}, maps the minimal wire
 * {@code BatchGetItemInput} onto a real AWS SDK {@link BatchGetItemRequest},
 * runs the DBE beacon-rewrite input transform, and maps every table's keys
 * back to the wire shape.
 */
public final class BatchGetItemInputTransformHandler
        implements BatchGetItemInputTransformOperation {

    private final TransformsClientGuard guard;
    private final OperationWrapper wrapper;
    private final DdbItemCodec itemCodec;

    public BatchGetItemInputTransformHandler(
            TransformsClientGuard guard, OperationWrapper wrapper, DdbItemCodec itemCodec) {
        this.guard = guard;
        this.wrapper = wrapper;
        this.itemCodec = itemCodec;
    }

    @Override
    public BatchGetItemInputTransformOutput batchGetItemInputTransform(
            BatchGetItemInputTransformInput input, RequestContext context) {
        return wrapper.invoke("BatchGetItemInputTransform", () -> {
            TransformsClient client = guard.resolve(input.getClientId());
            BatchGetItemInput wireInput = input.getSdkInput();

            Map<String, software.amazon.awssdk.services.dynamodb.model.KeysAndAttributes> sdkRequestItems =
                new LinkedHashMap<>();
            for (Map.Entry<String, KeysAndAttributes> table
                    : wireInput.getRequestItems().entrySet()) {
                List<Map<String, software.amazon.awssdk.services.dynamodb.model.AttributeValue>> keys =
                    new ArrayList<>(table.getValue().getKeys().size());
                for (Map<String, AttributeValue> key : table.getValue().getKeys()) {
                    keys.add(itemCodec.toDdb(key));
                }
                sdkRequestItems.put(table.getKey(),
                    software.amazon.awssdk.services.dynamodb.model.KeysAndAttributes.builder()
                        .keys(keys)
                        .build());
            }
            BatchGetItemRequest sdkInput = BatchGetItemRequest.builder()
                .requestItems(sdkRequestItems)
                .build();

            BatchGetItemRequest transformed = client.batchGetItemInputTransform(sdkInput);

            Map<String, KeysAndAttributes> wireRequestItems = new LinkedHashMap<>();
            for (Map.Entry<String, software.amazon.awssdk.services.dynamodb.model.KeysAndAttributes> table
                    : transformed.requestItems().entrySet()) {
                List<Map<String, AttributeValue>> keys =
                    new ArrayList<>(table.getValue().keys().size());
                for (Map<String, software.amazon.awssdk.services.dynamodb.model.AttributeValue> key
                        : table.getValue().keys()) {
                    keys.add(itemCodec.toModel(key));
                }
                wireRequestItems.put(table.getKey(),
                    KeysAndAttributes.builder().keys(keys).build());
            }

            return BatchGetItemInputTransformOutput.builder()
                .transformedInput(BatchGetItemInput.builder()
                    .requestItems(wireRequestItems)
                    .build())
                .build();
        });
    }
}
