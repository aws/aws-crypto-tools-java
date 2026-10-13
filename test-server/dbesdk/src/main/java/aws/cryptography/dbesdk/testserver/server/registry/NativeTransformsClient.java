package aws.cryptography.dbesdk.testserver.server.registry;

import aws.cryptography.dbesdk.testserver.server.error.DbesdkClientException;
import software.amazon.awssdk.services.dynamodb.model.BatchExecuteStatementRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchExecuteStatementResponse;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemResponse;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemResponse;
import software.amazon.awssdk.services.dynamodb.model.ExecuteStatementRequest;
import software.amazon.awssdk.services.dynamodb.model.ExecuteStatementResponse;
import software.amazon.awssdk.services.dynamodb.model.ExecuteTransactionRequest;
import software.amazon.awssdk.services.dynamodb.model.ExecuteTransactionResponse;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemResponse;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryResponse;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import software.amazon.awssdk.services.dynamodb.model.TransactGetItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactGetItemsResponse;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsResponse;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemResponse;
import software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms.DynamoDbEncryptionTransforms;

/**
 * A {@link TransformsClient} backed by the native (non-Dafny)
 * {@link DynamoDbEncryptionTransforms}. Each call delegates to the native
 * client; any failure it raises (a transforms/validation error, or an
 * item-encryptor failure surfaced through the item cryptor) is rethrown as
 * {@link DbesdkClientException} so the operation wrapper forwards it as
 * {@code DBESDKClientError} with the message unmodified.
 */
public final class NativeTransformsClient implements TransformsClient {

    private final DynamoDbEncryptionTransforms transforms;

    public NativeTransformsClient(DynamoDbEncryptionTransforms transforms) {
        this.transforms = transforms;
    }

    @Override
    public PutItemRequest putItemInputTransform(PutItemRequest sdkInput) throws DbesdkClientException {
        try {
            return transforms.putItemInputTransform(sdkInput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public PutItemResponse putItemOutputTransform(PutItemRequest originalInput, PutItemResponse sdkOutput)
        throws DbesdkClientException {
        try {
            return transforms.putItemOutputTransform(originalInput, sdkOutput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public GetItemRequest getItemInputTransform(GetItemRequest sdkInput) throws DbesdkClientException {
        try {
            return transforms.getItemInputTransform(sdkInput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public GetItemResponse getItemOutputTransform(GetItemRequest originalInput, GetItemResponse sdkOutput)
        throws DbesdkClientException {
        try {
            return transforms.getItemOutputTransform(originalInput, sdkOutput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public BatchGetItemRequest batchGetItemInputTransform(BatchGetItemRequest sdkInput)
        throws DbesdkClientException {
        try {
            return transforms.batchGetItemInputTransform(sdkInput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public BatchWriteItemRequest batchWriteItemInputTransform(BatchWriteItemRequest sdkInput)
        throws DbesdkClientException {
        try {
            return transforms.batchWriteItemInputTransform(sdkInput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public BatchWriteItemResponse batchWriteItemOutputTransform(
            BatchWriteItemRequest originalInput, BatchWriteItemResponse sdkOutput) throws DbesdkClientException {
        try {
            return transforms.batchWriteItemOutputTransform(originalInput, sdkOutput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public TransactWriteItemsRequest transactWriteItemsInputTransform(TransactWriteItemsRequest sdkInput)
        throws DbesdkClientException {
        try {
            return transforms.transactWriteItemsInputTransform(sdkInput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public ScanResponse scanOutputTransform(ScanRequest originalInput, ScanResponse sdkOutput)
        throws DbesdkClientException {
        try {
            return transforms.scanOutputTransform(originalInput, sdkOutput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public QueryResponse queryOutputTransform(QueryRequest originalInput, QueryResponse sdkOutput)
        throws DbesdkClientException {
        try {
            return transforms.queryOutputTransform(originalInput, sdkOutput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public BatchGetItemResponse batchGetItemOutputTransform(
            BatchGetItemRequest originalInput, BatchGetItemResponse sdkOutput) throws DbesdkClientException {
        try {
            return transforms.batchGetItemOutputTransform(originalInput, sdkOutput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public ExecuteStatementRequest executeStatementInputTransform(ExecuteStatementRequest sdkInput)
        throws DbesdkClientException {
        try {
            return transforms.executeStatementInputTransform(sdkInput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public ExecuteStatementResponse executeStatementOutputTransform(
            ExecuteStatementRequest originalInput, ExecuteStatementResponse sdkOutput) throws DbesdkClientException {
        try {
            return transforms.executeStatementOutputTransform(originalInput, sdkOutput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public BatchExecuteStatementRequest batchExecuteStatementInputTransform(
            BatchExecuteStatementRequest sdkInput) throws DbesdkClientException {
        try {
            return transforms.batchExecuteStatementInputTransform(sdkInput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public BatchExecuteStatementResponse batchExecuteStatementOutputTransform(
            BatchExecuteStatementRequest originalInput, BatchExecuteStatementResponse sdkOutput)
        throws DbesdkClientException {
        try {
            return transforms.batchExecuteStatementOutputTransform(originalInput, sdkOutput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public ExecuteTransactionRequest executeTransactionInputTransform(ExecuteTransactionRequest sdkInput)
        throws DbesdkClientException {
        try {
            return transforms.executeTransactionInputTransform(sdkInput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public ExecuteTransactionResponse executeTransactionOutputTransform(
            ExecuteTransactionRequest originalInput, ExecuteTransactionResponse sdkOutput)
        throws DbesdkClientException {
        try {
            return transforms.executeTransactionOutputTransform(originalInput, sdkOutput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public ScanRequest scanInputTransform(ScanRequest sdkInput) throws DbesdkClientException {
        try {
            return transforms.scanInputTransform(sdkInput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public QueryRequest queryInputTransform(QueryRequest sdkInput) throws DbesdkClientException {
        try {
            return transforms.queryInputTransform(sdkInput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public UpdateItemRequest updateItemInputTransform(UpdateItemRequest sdkInput) throws DbesdkClientException {
        try {
            return transforms.updateItemInputTransform(sdkInput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public UpdateItemResponse updateItemOutputTransform(
            UpdateItemRequest originalInput, UpdateItemResponse sdkOutput) throws DbesdkClientException {
        try {
            return transforms.updateItemOutputTransform(originalInput, sdkOutput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public DeleteItemRequest deleteItemInputTransform(DeleteItemRequest sdkInput) throws DbesdkClientException {
        try {
            return transforms.deleteItemInputTransform(sdkInput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public DeleteItemResponse deleteItemOutputTransform(
            DeleteItemRequest originalInput, DeleteItemResponse sdkOutput) throws DbesdkClientException {
        try {
            return transforms.deleteItemOutputTransform(originalInput, sdkOutput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public TransactGetItemsRequest transactGetItemsInputTransform(TransactGetItemsRequest sdkInput)
        throws DbesdkClientException {
        try {
            return transforms.transactGetItemsInputTransform(sdkInput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public TransactGetItemsResponse transactGetItemsOutputTransform(
            TransactGetItemsRequest originalInput, TransactGetItemsResponse sdkOutput) throws DbesdkClientException {
        try {
            return transforms.transactGetItemsOutputTransform(originalInput, sdkOutput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }

    @Override
    public TransactWriteItemsResponse transactWriteItemsOutputTransform(
            TransactWriteItemsRequest originalInput, TransactWriteItemsResponse sdkOutput) throws DbesdkClientException {
        try {
            return transforms.transactWriteItemsOutputTransform(originalInput, sdkOutput);
        } catch (RuntimeException failure) {
            throw new DbesdkClientException(failure);
        }
    }
}
