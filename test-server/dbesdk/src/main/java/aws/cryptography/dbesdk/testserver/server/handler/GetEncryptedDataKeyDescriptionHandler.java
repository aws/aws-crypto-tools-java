package aws.cryptography.dbesdk.testserver.server.handler;

import aws.cryptography.dbesdk.testserver.server.error.OperationWrapper;
import aws.cryptography.dbesdk.testserver.server.model.EncryptedDataKeyDescription;
import aws.cryptography.dbesdk.testserver.server.model.EncryptedDataKeyDescriptionSource;
import aws.cryptography.dbesdk.testserver.server.model.GetEncryptedDataKeyDescriptionInput;
import aws.cryptography.dbesdk.testserver.server.model.GetEncryptedDataKeyDescriptionOutput;
import aws.cryptography.dbesdk.testserver.server.service.GetEncryptedDataKeyDescriptionOperation;
import java.util.ArrayList;
import java.util.List;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryption;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.model.DynamoDbEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.model.GetEncryptedDataKeyDescriptionUnion;
import software.amazon.smithy.java.server.RequestContext;

/**
 * Parses a structured-encryption header — given either raw header bytes or an
 * encrypted DynamoDB item whose {@code aws_dbe_head} attribute carries it — into
 * the list of encrypted data key descriptions it contains, using the real DBE
 * {@link DynamoDbEncryption} client. Stateless: this operation has no
 * {@code ClientId} and needs no per-table config, so a single client built from
 * an empty {@link DynamoDbEncryptionConfig} is reused for every call.
 */
public final class GetEncryptedDataKeyDescriptionHandler
        implements GetEncryptedDataKeyDescriptionOperation {

    private final OperationWrapper wrapper;
    private final DdbItemCodec itemCodec;
    private final DynamoDbEncryption dbe;

    public GetEncryptedDataKeyDescriptionHandler(OperationWrapper wrapper, DdbItemCodec itemCodec) {
        this.wrapper = wrapper;
        this.itemCodec = itemCodec;
        this.dbe = DynamoDbEncryption.builder()
            .DynamoDbEncryptionConfig(DynamoDbEncryptionConfig.builder().build())
            .build();
    }

    @Override
    public GetEncryptedDataKeyDescriptionOutput getEncryptedDataKeyDescription(
            GetEncryptedDataKeyDescriptionInput input, RequestContext context) {
        return wrapper.invoke("GetEncryptedDataKeyDescription", () -> {
            EncryptedDataKeyDescriptionSource wireSource = input.getInput();

            GetEncryptedDataKeyDescriptionUnion.Builder sdkSource =
                GetEncryptedDataKeyDescriptionUnion.builder();
            if (wireSource instanceof EncryptedDataKeyDescriptionSource.HeaderMember header) {
                sdkSource.header(header.header());
            } else if (wireSource instanceof EncryptedDataKeyDescriptionSource.ItemMember item) {
                sdkSource.item(itemCodec.toDdb(item.item()));
            } else {
                throw new IllegalArgumentException(
                    "EncryptedDataKeyDescriptionSource had no variant member set");
            }

            software.amazon.cryptography.dbencryptionsdk.dynamodb.model.GetEncryptedDataKeyDescriptionOutput
                sdkOutput = dbe.GetEncryptedDataKeyDescription(
                    software.amazon.cryptography.dbencryptionsdk.dynamodb.model
                        .GetEncryptedDataKeyDescriptionInput.builder()
                        .input(sdkSource.build())
                        .build());

            List<EncryptedDataKeyDescription> wireDescriptions =
                new ArrayList<>(sdkOutput.EncryptedDataKeyDescriptionOutput().size());
            for (software.amazon.cryptography.dbencryptionsdk.dynamodb.model.EncryptedDataKeyDescription d
                    : sdkOutput.EncryptedDataKeyDescriptionOutput()) {
                EncryptedDataKeyDescription.Builder builder = EncryptedDataKeyDescription.builder()
                    .keyProviderId(d.keyProviderId())
                    .keyProviderInfo(d.keyProviderInfo());
                if (d.branchKeyId() != null) {
                    builder.branchKeyId(d.branchKeyId());
                }
                if (d.branchKeyVersion() != null) {
                    builder.branchKeyVersion(d.branchKeyVersion());
                }
                wireDescriptions.add(builder.build());
            }

            return GetEncryptedDataKeyDescriptionOutput.builder()
                .descriptions(wireDescriptions)
                .build();
        });
    }
}
