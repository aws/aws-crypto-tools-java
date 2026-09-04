package aws.cryptography.dbesdk.testserver.server.registry;

import aws.cryptography.dbesdk.testserver.server.error.DbesdkClientException;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.transforms.DynamoDbEncryptionTransforms;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.transforms.model.GetItemOutputTransformInput;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.transforms.model.PutItemInputTransformInput;

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
}
