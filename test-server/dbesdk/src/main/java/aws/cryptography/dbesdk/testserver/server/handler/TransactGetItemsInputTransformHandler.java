package aws.cryptography.dbesdk.testserver.server.handler;

import aws.cryptography.dbesdk.testserver.server.error.OperationWrapper;
import aws.cryptography.dbesdk.testserver.server.model.Get;
import aws.cryptography.dbesdk.testserver.server.model.TransactGetItem;
import aws.cryptography.dbesdk.testserver.server.model.TransactGetItemsInput;
import aws.cryptography.dbesdk.testserver.server.model.TransactGetItemsInputTransformInput;
import aws.cryptography.dbesdk.testserver.server.model.TransactGetItemsInputTransformOutput;
import aws.cryptography.dbesdk.testserver.server.registry.TransformsClient;
import aws.cryptography.dbesdk.testserver.server.service.TransactGetItemsInputTransformOperation;
import java.util.ArrayList;
import java.util.List;
import software.amazon.smithy.java.server.RequestContext;

/**
 * Resolves the transforms {@code ClientId}, maps the minimal wire
 * {@code TransactGetItemsInput} onto a real AWS SDK
 * {@link software.amazon.awssdk.services.dynamodb.model.TransactGetItemsRequest},
 * runs the DBE beacon-rewrite input transform, and maps every Get action's
 * key back to the wire shape.
 */
public final class TransactGetItemsInputTransformHandler
        implements TransactGetItemsInputTransformOperation {

    private final TransformsClientGuard guard;
    private final OperationWrapper wrapper;
    private final DdbItemCodec itemCodec;

    public TransactGetItemsInputTransformHandler(
            TransformsClientGuard guard, OperationWrapper wrapper, DdbItemCodec itemCodec) {
        this.guard = guard;
        this.wrapper = wrapper;
        this.itemCodec = itemCodec;
    }

    @Override
    public TransactGetItemsInputTransformOutput transactGetItemsInputTransform(
            TransactGetItemsInputTransformInput input, RequestContext context) {
        return wrapper.invoke("TransactGetItemsInputTransform", () -> {
            TransformsClient client = guard.resolve(input.getClientId());
            TransactGetItemsInput wireInput = input.getSdkInput();

            List<software.amazon.awssdk.services.dynamodb.model.TransactGetItem> sdkItems =
                new ArrayList<>(wireInput.getTransactItems().size());
            for (TransactGetItem item : wireInput.getTransactItems()) {
                sdkItems.add(toSdkTransactGetItem(item));
            }

            software.amazon.awssdk.services.dynamodb.model.TransactGetItemsRequest transformed =
                client.transactGetItemsInputTransform(
                    software.amazon.awssdk.services.dynamodb.model.TransactGetItemsRequest.builder()
                        .transactItems(sdkItems)
                        .build());

            List<TransactGetItem> wireItems = new ArrayList<>(transformed.transactItems().size());
            for (software.amazon.awssdk.services.dynamodb.model.TransactGetItem item
                    : transformed.transactItems()) {
                wireItems.add(toWireTransactGetItem(item));
            }

            return TransactGetItemsInputTransformOutput.builder()
                .transformedInput(TransactGetItemsInput.builder()
                    .transactItems(wireItems)
                    .build())
                .build();
        });
    }

    private software.amazon.awssdk.services.dynamodb.model.TransactGetItem toSdkTransactGetItem(
            TransactGetItem item) {
        Get get = item.getGet();
        if (get == null) {
            throw new IllegalArgumentException(
                "TransactGetItem must set a get action (only Get is modeled)");
        }
        return software.amazon.awssdk.services.dynamodb.model.TransactGetItem.builder()
            .get(software.amazon.awssdk.services.dynamodb.model.Get.builder()
                .tableName(get.getTableName())
                .key(itemCodec.toDdb(get.getKey()))
                .build())
            .build();
    }

    private TransactGetItem toWireTransactGetItem(
            software.amazon.awssdk.services.dynamodb.model.TransactGetItem item) {
        software.amazon.awssdk.services.dynamodb.model.Get get = item.get();
        if (get == null) {
            throw new IllegalStateException(
                "DBE returned a TransactGetItem with no get action");
        }
        return TransactGetItem.builder()
            .get(Get.builder()
                .tableName(get.tableName())
                .key(itemCodec.toModel(get.key()))
                .build())
            .build();
    }
}
