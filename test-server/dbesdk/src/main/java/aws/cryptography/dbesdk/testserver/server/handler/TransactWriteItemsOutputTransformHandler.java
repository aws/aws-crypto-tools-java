package aws.cryptography.dbesdk.testserver.server.handler;

import aws.cryptography.dbesdk.testserver.server.error.OperationWrapper;
import aws.cryptography.dbesdk.testserver.server.model.Put;
import aws.cryptography.dbesdk.testserver.server.model.TransactWriteItem;
import aws.cryptography.dbesdk.testserver.server.model.TransactWriteItemsInput;
import aws.cryptography.dbesdk.testserver.server.model.TransactWriteItemsOutput;
import aws.cryptography.dbesdk.testserver.server.model.TransactWriteItemsOutputTransformInput;
import aws.cryptography.dbesdk.testserver.server.model.TransactWriteItemsOutputTransformOutput;
import aws.cryptography.dbesdk.testserver.server.registry.TransformsClient;
import aws.cryptography.dbesdk.testserver.server.service.TransactWriteItemsOutputTransformOperation;
import java.util.ArrayList;
import java.util.List;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsResponse;
import software.amazon.smithy.java.server.RequestContext;

/**
 * Resolves the transforms {@code ClientId}, rebuilds the real AWS SDK
 * {@link TransactWriteItemsRequest} from the wire {@code TransactWriteItemsInput}
 * (mirroring the input transform's Put-only mapping), and runs the DBE
 * decrypt-after transform against an empty {@link TransactWriteItemsResponse}
 * (the operation returns no data on success; {@code TransactWriteItemsOutput}
 * carries no members).
 */
public final class TransactWriteItemsOutputTransformHandler
        implements TransactWriteItemsOutputTransformOperation {

    private final TransformsClientGuard guard;
    private final OperationWrapper wrapper;
    private final DdbItemCodec itemCodec;

    public TransactWriteItemsOutputTransformHandler(
            TransformsClientGuard guard, OperationWrapper wrapper, DdbItemCodec itemCodec) {
        this.guard = guard;
        this.wrapper = wrapper;
        this.itemCodec = itemCodec;
    }

    @Override
    public TransactWriteItemsOutputTransformOutput transactWriteItemsOutputTransform(
            TransactWriteItemsOutputTransformInput input, RequestContext context) {
        return wrapper.invoke("TransactWriteItemsOutputTransform", () -> {
            TransformsClient client = guard.resolve(input.getClientId());
            TransactWriteItemsInput wireInput = input.getOriginalInput();

            List<software.amazon.awssdk.services.dynamodb.model.TransactWriteItem> sdkItems =
                new ArrayList<>(wireInput.getTransactItems().size());
            for (TransactWriteItem item : wireInput.getTransactItems()) {
                Put put = item.getPut();
                if (put == null) {
                    throw new IllegalArgumentException(
                        "TransactWriteItem must set a put action (only Put is modeled)");
                }
                sdkItems.add(software.amazon.awssdk.services.dynamodb.model.TransactWriteItem.builder()
                    .put(software.amazon.awssdk.services.dynamodb.model.Put.builder()
                        .tableName(put.getTableName())
                        .item(itemCodec.toDdb(put.getItem()))
                        .build())
                    .build());
            }
            TransactWriteItemsRequest originalInput = TransactWriteItemsRequest.builder()
                .transactItems(sdkItems)
                .build();

            client.transactWriteItemsOutputTransform(
                originalInput, TransactWriteItemsResponse.builder().build());

            return TransactWriteItemsOutputTransformOutput.builder()
                .transformedOutput(TransactWriteItemsOutput.builder().build())
                .build();
        });
    }
}
