package aws.cryptography.dbesdk.testserver.server.registry;

import aws.cryptography.dbesdk.testserver.server.error.DbesdkClientException;
import software.amazon.awssdk.services.dynamodb.model.BatchExecuteStatementRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemResponse;
import software.amazon.awssdk.services.dynamodb.model.ExecuteStatementRequest;
import software.amazon.awssdk.services.dynamodb.model.ExecuteTransactionRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryResponse;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;

/**
 * A single configured DBE DDB-SDK transforms client stored in the
 * {@link TransformsClientRegistry}. On the Java server this wraps a real
 * {@link software.amazon.cryptography.dbencryptionsdk.dynamodb.transforms.DynamoDbEncryptionTransforms}
 * (see {@code RealTransformsClient}).
 *
 * <p>Unlike the {@link DbesdkClient} item encryptor, which operates on an
 * already-materialized item map, the transforms client operates on real AWS SDK
 * DynamoDB request/response objects — the interceptor hooks a DDB call would
 * pass through. This sub-round wires the encrypt-before {@code PutItemInput}
 * transform and the decrypt-after {@code GetItemOutput} transform; the remaining
 * DDB operations are added in later sub-rounds.
 *
 * <p>Both methods declare {@link DbesdkClientException}: implementations catch
 * exceptions thrown by the underlying DBE library and rethrow them wrapped, so
 * the operation wrapper forwards them as {@code DBESDKClientError} with the DBE
 * message unmodified.
 */
public interface TransformsClient {

    /**
     * Transform a DynamoDB PutItem input, encrypting the item per the table's
     * Crypto Actions.
     *
     * @param sdkInput the PutItem request to transform.
     * @return the transformed PutItem request whose item is now encrypted.
     * @throws DbesdkClientException if the DBE library fails.
     */
    PutItemRequest putItemInputTransform(PutItemRequest sdkInput) throws DbesdkClientException;

    /**
     * Transform a DynamoDB GetItem output, decrypting the returned item.
     *
     * @param originalInput the GetItem request that produced {@code sdkOutput}.
     * @param sdkOutput the GetItem response to transform.
     * @return the transformed GetItem response whose item (when present) is
     *     decrypted.
     * @throws DbesdkClientException if the DBE library fails.
     */
    GetItemResponse getItemOutputTransform(GetItemRequest originalInput, GetItemResponse sdkOutput)
        throws DbesdkClientException;

    /**
     * Transform a DynamoDB BatchWriteItem input, encrypting the item of every
     * PutRequest and passing DeleteRequests through unchanged.
     *
     * @param sdkInput the BatchWriteItem request to transform.
     * @return the transformed request whose PutRequest items are encrypted.
     * @throws DbesdkClientException if the DBE library fails.
     */
    BatchWriteItemRequest batchWriteItemInputTransform(BatchWriteItemRequest sdkInput)
        throws DbesdkClientException;

    /**
     * Transform a DynamoDB BatchWriteItem output, restoring each unprocessed
     * PutRequest item to its original plaintext value (matched against
     * {@code originalInput} by primary key). A response with no UnprocessedItems
     * is returned unchanged.
     *
     * @param originalInput the original (plaintext) BatchWriteItem request.
     * @param sdkOutput the BatchWriteItem response to transform.
     * @return the transformed response whose UnprocessedItems are plaintext.
     * @throws DbesdkClientException if the DBE library fails.
     */
    BatchWriteItemResponse batchWriteItemOutputTransform(
            BatchWriteItemRequest originalInput, BatchWriteItemResponse sdkOutput)
        throws DbesdkClientException;

    /**
     * Transform a DynamoDB TransactWriteItems input, encrypting the item of
     * every Put action.
     *
     * @param sdkInput the TransactWriteItems request to transform.
     * @return the transformed request whose Put items are encrypted.
     * @throws DbesdkClientException if the DBE library fails.
     */
    TransactWriteItemsRequest transactWriteItemsInputTransform(TransactWriteItemsRequest sdkInput)
        throws DbesdkClientException;

    /**
     * Transform a DynamoDB Scan output, decrypting every returned item.
     *
     * @param originalInput the Scan request that produced {@code sdkOutput}.
     * @param sdkOutput the Scan response to transform.
     * @return the transformed response whose items are decrypted.
     * @throws DbesdkClientException if the DBE library fails.
     */
    ScanResponse scanOutputTransform(ScanRequest originalInput, ScanResponse sdkOutput)
        throws DbesdkClientException;

    /**
     * Transform a DynamoDB Query output, decrypting every returned item.
     *
     * @param originalInput the Query request that produced {@code sdkOutput}.
     * @param sdkOutput the Query response to transform.
     * @return the transformed response whose items are decrypted.
     * @throws DbesdkClientException if the DBE library fails.
     */
    QueryResponse queryOutputTransform(QueryRequest originalInput, QueryResponse sdkOutput)
        throws DbesdkClientException;

    /**
     * Transform a DynamoDB BatchGetItem output, decrypting every returned item
     * across all tables.
     *
     * @param originalInput the BatchGetItem request that produced {@code sdkOutput}.
     * @param sdkOutput the BatchGetItem response to transform.
     * @return the transformed response whose items are decrypted.
     * @throws DbesdkClientException if the DBE library fails.
     */
    BatchGetItemResponse batchGetItemOutputTransform(
            BatchGetItemRequest originalInput, BatchGetItemResponse sdkOutput)
        throws DbesdkClientException;

    /**
     * Validate a PartiQL ExecuteStatement input. Throws when the statement
     * targets an encrypted table; otherwise returns the input unchanged.
     *
     * @throws DbesdkClientException if the DBE library rejects the statement.
     */
    ExecuteStatementRequest executeStatementInputTransform(ExecuteStatementRequest sdkInput)
        throws DbesdkClientException;

    /**
     * Validate a PartiQL BatchExecuteStatement input. Throws when any statement
     * targets an encrypted table; otherwise returns the input unchanged.
     *
     * @throws DbesdkClientException if the DBE library rejects a statement.
     */
    BatchExecuteStatementRequest batchExecuteStatementInputTransform(
            BatchExecuteStatementRequest sdkInput)
        throws DbesdkClientException;

    /**
     * Validate a PartiQL ExecuteTransaction input. Throws when any transact
     * statement targets an encrypted table; otherwise returns the input
     * unchanged.
     *
     * @throws DbesdkClientException if the DBE library rejects a statement.
     */
    ExecuteTransactionRequest executeTransactionInputTransform(
            ExecuteTransactionRequest sdkInput)
        throws DbesdkClientException;
}
