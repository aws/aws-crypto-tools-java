package aws.cryptography.dbesdk.testserver.server.handler;

import aws.cryptography.dbesdk.testserver.server.error.OperationWrapper;
import aws.cryptography.dbesdk.testserver.server.model.Get;
import aws.cryptography.dbesdk.testserver.server.model.ItemResponse;
import aws.cryptography.dbesdk.testserver.server.model.TransactGetItem;
import aws.cryptography.dbesdk.testserver.server.model.TransactGetItemsInput;
import aws.cryptography.dbesdk.testserver.server.model.TransactGetItemsOutput;
import aws.cryptography.dbesdk.testserver.server.model.TransactGetItemsOutputTransformInput;
import aws.cryptography.dbesdk.testserver.server.model.TransactGetItemsOutputTransformOutput;
import aws.cryptography.dbesdk.testserver.server.registry.TransformsClient;
import aws.cryptography.dbesdk.testserver.server.service.TransactGetItemsOutputTransformOperation;
import java.util.ArrayList;
import java.util.List;
import software.amazon.awssdk.services.dynamodb.model.TransactGetItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactGetItemsResponse;
import software.amazon.smithy.java.server.RequestContext;

/**
 * Resolves the transforms {@code ClientId}, maps the minimal wire
 * {@code TransactGetItemsOutput} / {@code TransactGetItemsInput} onto real AWS
 * SDK {@link TransactGetItemsResponse} / {@link TransactGetItemsRequest}, runs
 * the DBE decrypt-after transform, and maps every decrypted item response back.
 */
public final class TransactGetItemsOutputTransformHandler
        implements TransactGetItemsOutputTransformOperation {

    private final TransformsClientGuard guard;
    private final OperationWrapper wrapper;
    private final DdbItemCodec itemCodec;

    public TransactGetItemsOutputTransformHandler(
            TransformsClientGuard guard, OperationWrapper wrapper, DdbItemCodec itemCodec) {
        this.guard = guard;
        this.wrapper = wrapper;
        this.itemCodec = itemCodec;
    }

    @Override
    public TransactGetItemsOutputTransformOutput transactGetItemsOutputTransform(
            TransactGetItemsOutputTransformInput input, RequestContext context) {
        return wrapper.invoke("TransactGetItemsOutputTransform", () -> {
            TransformsClient client = guard.resolve(input.getClientId());
            TransactGetItemsInput wireInput = input.getOriginalInput();
            TransactGetItemsOutput wireOutput = input.getSdkOutput();

            List<software.amazon.awssdk.services.dynamodb.model.TransactGetItem> sdkItems =
                new ArrayList<>(wireInput.getTransactItems().size());
            for (TransactGetItem item : wireInput.getTransactItems()) {
                Get get = item.getGet();
                sdkItems.add(software.amazon.awssdk.services.dynamodb.model.TransactGetItem.builder()
                    .get(software.amazon.awssdk.services.dynamodb.model.Get.builder()
                        .tableName(get.getTableName())
                        .key(itemCodec.toDdb(get.getKey()))
                        .build())
                    .build());
            }
            TransactGetItemsRequest originalInput = TransactGetItemsRequest.builder()
                .transactItems(sdkItems)
                .build();

            TransactGetItemsResponse.Builder sdkOutput = TransactGetItemsResponse.builder();
            if (wireOutput.hasResponses()) {
                sdkOutput.responses(toSdkResponses(wireOutput.getResponses()));
            }

            TransactGetItemsResponse transformed =
                client.transactGetItemsOutputTransform(originalInput, sdkOutput.build());

            TransactGetItemsOutput.Builder result = TransactGetItemsOutput.builder();
            if (transformed.hasResponses()) {
                result.responses(toWireResponses(transformed.responses()));
            }
            return TransactGetItemsOutputTransformOutput.builder()
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
