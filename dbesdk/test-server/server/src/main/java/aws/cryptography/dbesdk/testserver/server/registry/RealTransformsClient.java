package aws.cryptography.dbesdk.testserver.server.registry;

import aws.cryptography.dbesdk.testserver.server.error.DbesdkClientException;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryResponse;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.transforms.DynamoDbEncryptionTransforms;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.transforms.model.BatchGetItemOutputTransformInput;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.transforms.model.BatchWriteItemInputTransformInput;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.transforms.model.GetItemOutputTransformInput;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.transforms.model.PutItemInputTransformInput;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.transforms.model.QueryOutputTransformInput;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.transforms.model.ScanOutputTransformInput;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.transforms.model.TransactWriteItemsInputTransformInput;

/**
 * A configured {@link TransformsClient} backed by the real
 * {@link DynamoDbEncryptionTransforms} from the AWS Database Encryption SDK for
 * DynamoDB. Every call reaches the real DBE library. Any exception the library
 * throws is caught and rethrown as {@link DbesdkClientException} so the
 * operation wrapper forwards it as {@code DBESDKClientError} carrying the DBE
 * message unmodified.
 */
public final class RealTransformsClient implements TransformsClient {

    private final DynamoDbEncryptionTransforms transforms;

    public RealTransformsClient(DynamoDbEncryptionTransforms transforms) {
        this.transforms = transforms;
    }

    @Override
    public PutItemRequest putItemInputTransform(PutItemRequest sdkInput)
        throws DbesdkClientException {
        try {
            return transforms.PutItemInputTransform(
                PutItemInputTransformInput.builder().sdkInput(sdkInput).build()
            ).transformedInput();
        } catch (Exception dbeFailure) {
            throw new DbesdkClientException(dbeFailure);
        }
    }

    @Override
    public GetItemResponse getItemOutputTransform(
            GetItemRequest originalInput, GetItemResponse sdkOutput)
        throws DbesdkClientException {
        try {
            return transforms.GetItemOutputTransform(
                GetItemOutputTransformInput.builder()
                    .originalInput(originalInput)
                    .sdkOutput(sdkOutput)
                    .build()
            ).transformedOutput();
        } catch (Exception dbeFailure) {
            throw new DbesdkClientException(dbeFailure);
        }
    }

    @Override
    public BatchWriteItemRequest batchWriteItemInputTransform(BatchWriteItemRequest sdkInput)
        throws DbesdkClientException {
        try {
            return transforms.BatchWriteItemInputTransform(
                BatchWriteItemInputTransformInput.builder().sdkInput(sdkInput).build()
            ).transformedInput();
        } catch (Exception dbeFailure) {
            throw new DbesdkClientException(dbeFailure);
        }
    }

    @Override
    public TransactWriteItemsRequest transactWriteItemsInputTransform(
            TransactWriteItemsRequest sdkInput)
        throws DbesdkClientException {
        try {
            return transforms.TransactWriteItemsInputTransform(
                TransactWriteItemsInputTransformInput.builder().sdkInput(sdkInput).build()
            ).transformedInput();
        } catch (Exception dbeFailure) {
            throw new DbesdkClientException(dbeFailure);
        }
    }

    @Override
    public ScanResponse scanOutputTransform(ScanRequest originalInput, ScanResponse sdkOutput)
        throws DbesdkClientException {
        try {
            return transforms.ScanOutputTransform(
                ScanOutputTransformInput.builder()
                    .originalInput(originalInput)
                    .sdkOutput(sdkOutput)
                    .build()
            ).transformedOutput();
        } catch (Exception dbeFailure) {
            throw new DbesdkClientException(dbeFailure);
        }
    }

    @Override
    public QueryResponse queryOutputTransform(QueryRequest originalInput, QueryResponse sdkOutput)
        throws DbesdkClientException {
        try {
            return transforms.QueryOutputTransform(
                QueryOutputTransformInput.builder()
                    .originalInput(originalInput)
                    .sdkOutput(sdkOutput)
                    .build()
            ).transformedOutput();
        } catch (Exception dbeFailure) {
            throw new DbesdkClientException(dbeFailure);
        }
    }

    @Override
    public BatchGetItemResponse batchGetItemOutputTransform(
            BatchGetItemRequest originalInput, BatchGetItemResponse sdkOutput)
        throws DbesdkClientException {
        try {
            return transforms.BatchGetItemOutputTransform(
                BatchGetItemOutputTransformInput.builder()
                    .originalInput(originalInput)
                    .sdkOutput(sdkOutput)
                    .build()
            ).transformedOutput();
        } catch (Exception dbeFailure) {
            throw new DbesdkClientException(dbeFailure);
        }
    }
}
