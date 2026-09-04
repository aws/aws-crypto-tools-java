package aws.cryptography.dbesdk.testserver.server.handler;

import aws.cryptography.dbesdk.testserver.server.error.OperationWrapper;
import aws.cryptography.dbesdk.testserver.server.model.BatchWriteItemInput;
import aws.cryptography.dbesdk.testserver.server.model.BatchWriteItemInputTransformInput;
import aws.cryptography.dbesdk.testserver.server.model.BatchWriteItemInputTransformOutput;
import aws.cryptography.dbesdk.testserver.server.model.DeleteRequest;
import aws.cryptography.dbesdk.testserver.server.model.PutRequest;
import aws.cryptography.dbesdk.testserver.server.model.WriteRequest;
import aws.cryptography.dbesdk.testserver.server.registry.TransformsClient;
import aws.cryptography.dbesdk.testserver.server.service.BatchWriteItemInputTransformOperation;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import software.amazon.smithy.java.server.RequestContext;

/**
 * Resolves the transforms {@code ClientId}, maps the minimal wire
 * {@code BatchWriteItemInput} onto a real AWS SDK
 * {@link software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest},
 * runs the DBE encrypt-before transform (which encrypts every PutRequest item
 * and leaves DeleteRequests untouched), and maps the transformed request back.
 */
public final class BatchWriteItemInputTransformHandler
        implements BatchWriteItemInputTransformOperation {

    private final TransformsClientGuard guard;
    private final OperationWrapper wrapper;
    private final DdbItemCodec itemCodec;

    public BatchWriteItemInputTransformHandler(
            TransformsClientGuard guard, OperationWrapper wrapper, DdbItemCodec itemCodec) {
        this.guard = guard;
        this.wrapper = wrapper;
        this.itemCodec = itemCodec;
    }

    @Override
    public BatchWriteItemInputTransformOutput batchWriteItemInputTransform(
            BatchWriteItemInputTransformInput input, RequestContext context) {
        return wrapper.invoke("BatchWriteItemInputTransform", () -> {
            TransformsClient client = guard.resolve(input.getClientId());
            BatchWriteItemInput wireInput = input.getSdkInput();

            Map<String, List<software.amazon.awssdk.services.dynamodb.model.WriteRequest>> sdkRequestItems =
                new LinkedHashMap<>();
            for (Map.Entry<String, List<WriteRequest>> table
                    : wireInput.getRequestItems().entrySet()) {
                List<software.amazon.awssdk.services.dynamodb.model.WriteRequest> sdkList =
                    new ArrayList<>(table.getValue().size());
                for (WriteRequest wr : table.getValue()) {
                    sdkList.add(toSdkWriteRequest(wr));
                }
                sdkRequestItems.put(table.getKey(), sdkList);
            }

            software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest transformed =
                client.batchWriteItemInputTransform(
                    software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest.builder()
                        .requestItems(sdkRequestItems)
                        .build());

            Map<String, List<WriteRequest>> wireRequestItems = new LinkedHashMap<>();
            for (Map.Entry<String, List<software.amazon.awssdk.services.dynamodb.model.WriteRequest>> table
                    : transformed.requestItems().entrySet()) {
                List<WriteRequest> wireList = new ArrayList<>(table.getValue().size());
                for (software.amazon.awssdk.services.dynamodb.model.WriteRequest wr
                        : table.getValue()) {
                    wireList.add(toWireWriteRequest(wr));
                }
                wireRequestItems.put(table.getKey(), wireList);
            }

            return BatchWriteItemInputTransformOutput.builder()
                .transformedInput(BatchWriteItemInput.builder()
                    .requestItems(wireRequestItems)
                    .build())
                .build();
        });
    }

    private software.amazon.awssdk.services.dynamodb.model.WriteRequest toSdkWriteRequest(
            WriteRequest wr) {
        if (wr.getPutRequest() != null) {
            return software.amazon.awssdk.services.dynamodb.model.WriteRequest.builder()
                .putRequest(software.amazon.awssdk.services.dynamodb.model.PutRequest.builder()
                    .item(itemCodec.toDdb(wr.getPutRequest().getItem()))
                    .build())
                .build();
        }
        if (wr.getDeleteRequest() != null) {
            return software.amazon.awssdk.services.dynamodb.model.WriteRequest.builder()
                .deleteRequest(software.amazon.awssdk.services.dynamodb.model.DeleteRequest.builder()
                    .key(itemCodec.toDdb(wr.getDeleteRequest().getKey()))
                    .build())
                .build();
        }
        throw new IllegalArgumentException(
            "WriteRequest must set exactly one of putRequest or deleteRequest");
    }

    private WriteRequest toWireWriteRequest(
            software.amazon.awssdk.services.dynamodb.model.WriteRequest wr) {
        if (wr.putRequest() != null) {
            return WriteRequest.builder()
                .putRequest(PutRequest.builder()
                    .item(itemCodec.toModel(wr.putRequest().item()))
                    .build())
                .build();
        }
        if (wr.deleteRequest() != null) {
            return WriteRequest.builder()
                .deleteRequest(DeleteRequest.builder()
                    .key(itemCodec.toModel(wr.deleteRequest().key()))
                    .build())
                .build();
        }
        throw new IllegalStateException(
            "DBE returned a WriteRequest with neither putRequest nor deleteRequest");
    }
}
