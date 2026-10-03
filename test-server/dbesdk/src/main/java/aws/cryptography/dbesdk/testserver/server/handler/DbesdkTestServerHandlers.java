package aws.cryptography.dbesdk.testserver.server.handler;

import aws.cryptography.dbesdk.testserver.server.config.ConfigValidator;
import aws.cryptography.dbesdk.testserver.server.config.ItemEncryptorFactory;
import aws.cryptography.dbesdk.testserver.server.config.StructuredClientFactory;
import aws.cryptography.dbesdk.testserver.server.config.TransformsClientFactory;
import aws.cryptography.dbesdk.testserver.server.error.OperationWrapper;
import aws.cryptography.dbesdk.testserver.server.registry.ClientRegistry;
import aws.cryptography.dbesdk.testserver.server.registry.StructuredClientRegistry;
import aws.cryptography.dbesdk.testserver.server.registry.TransformsClientRegistry;
import aws.cryptography.dbesdk.testserver.server.service.DBESDKTestServer;
import aws.cryptography.dbesdk.testserver.server.service.GetNumberOfQueriesOperation;

/**
 * Wires the generated {@link DBESDKTestServer} service to the hand-written
 * operation handlers over one shared, thread-safe {@link ClientRegistry}. This
 * is the single assembly point the launcher (and the concurrency integration
 * test) use to obtain a fully-wired service instance.
 *
 * <p>All three handlers share the same registry so that a {@code ClientId}
 * minted by {@code CreateClient} resolves on subsequent
 * {@code EncryptItem}/{@code DecryptItem} calls, and the registry is the
 * single piece of shared mutable state exercised under concurrency.
 *
 * <p>{@code GetNumberOfQueries} has no handler and is wired to a stub that
 * throws {@link UnsupportedOperationException}; the server still starts and
 * every other operation works. Its real implementation would need to
 * replicate the DBE library's internal beacon sub-query fan-out logic, which
 * is not exposed on the public {@code DynamoDbEncryptionTransforms} /
 * {@code MaterialProviders} API this server depends on.
 */
public final class DbesdkTestServerHandlers {

    private final ClientRegistry registry;
    private final TransformsClientRegistry transformsRegistry;
    private final CreateClientHandler createClient;
    private final EncryptItemHandler encryptItem;
    private final DecryptItemHandler decryptItem;
    private final CreateTransformsClientHandler createTransformsClient;
    private final PutItemInputTransformHandler putItemInputTransform;
    private final PutItemOutputTransformHandler putItemOutputTransform;
    private final GetItemInputTransformHandler getItemInputTransform;
    private final GetItemOutputTransformHandler getItemOutputTransform;
    private final BatchGetItemInputTransformHandler batchGetItemInputTransform;
    private final BatchWriteItemInputTransformHandler batchWriteItemInputTransform;
    private final BatchWriteItemOutputTransformHandler batchWriteItemOutputTransform;
    private final TransactWriteItemsInputTransformHandler transactWriteItemsInputTransform;
    private final TransactWriteItemsOutputTransformHandler transactWriteItemsOutputTransform;
    private final ScanOutputTransformHandler scanOutputTransform;
    private final QueryOutputTransformHandler queryOutputTransform;
    private final BatchGetItemOutputTransformHandler batchGetItemOutputTransform;
    private final ScanInputTransformHandler scanInputTransform;
    private final QueryInputTransformHandler queryInputTransform;
    private final UpdateItemInputTransformHandler updateItemInputTransform;
    private final UpdateItemOutputTransformHandler updateItemOutputTransform;
    private final DeleteItemInputTransformHandler deleteItemInputTransform;
    private final DeleteItemOutputTransformHandler deleteItemOutputTransform;
    private final ExecuteStatementInputTransformHandler executeStatementInputTransform;
    private final ExecuteStatementOutputTransformHandler executeStatementOutputTransform;
    private final BatchExecuteStatementInputTransformHandler batchExecuteStatementInputTransform;
    private final BatchExecuteStatementOutputTransformHandler batchExecuteStatementOutputTransform;
    private final ExecuteTransactionInputTransformHandler executeTransactionInputTransform;
    private final ExecuteTransactionOutputTransformHandler executeTransactionOutputTransform;
    private final TransactGetItemsInputTransformHandler transactGetItemsInputTransform;
    private final TransactGetItemsOutputTransformHandler transactGetItemsOutputTransform;
    private final GetEncryptedDataKeyDescriptionHandler getEncryptedDataKeyDescription;
    private final CreateStructuredClientHandler createStructuredClient;
    private final EncryptStructureHandler encryptStructure;
    private final DecryptStructureHandler decryptStructure;
    private final EncryptPathStructureHandler encryptPathStructure;
    private final DecryptPathStructureHandler decryptPathStructure;
    private final ResolveAuthActionsHandler resolveAuthActions;

    public DbesdkTestServerHandlers() {
        this(new ClientRegistry());
    }

    public DbesdkTestServerHandlers(ClientRegistry registry) {
        this.registry = registry;
        this.transformsRegistry = new TransformsClientRegistry();
        OperationWrapper wrapper = new OperationWrapper();
        ConfigValidator validator = new ConfigValidator();
        ItemEncryptorFactory factory = new ItemEncryptorFactory();
        TransformsClientFactory transformsFactory = new TransformsClientFactory(factory);
        ClientIdGuard guard = new ClientIdGuard(registry);
        TransformsClientGuard transformsGuard = new TransformsClientGuard(transformsRegistry);
        DdbItemCodec itemCodec = new DdbItemCodec();
        WriteRequestCodec writeRequestCodec = new WriteRequestCodec(itemCodec);

        this.createClient = new CreateClientHandler(registry, validator, factory, wrapper);
        this.encryptItem = new EncryptItemHandler(guard, wrapper, itemCodec);
        this.decryptItem = new DecryptItemHandler(guard, wrapper, itemCodec);
        this.createTransformsClient =
            new CreateTransformsClientHandler(transformsRegistry, validator, transformsFactory, wrapper);
        this.putItemInputTransform =
            new PutItemInputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.putItemOutputTransform =
            new PutItemOutputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.getItemInputTransform =
            new GetItemInputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.getItemOutputTransform =
            new GetItemOutputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.batchGetItemInputTransform =
            new BatchGetItemInputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.batchWriteItemInputTransform =
            new BatchWriteItemInputTransformHandler(transformsGuard, wrapper, writeRequestCodec);
        this.batchWriteItemOutputTransform =
            new BatchWriteItemOutputTransformHandler(transformsGuard, wrapper, writeRequestCodec);
        this.transactWriteItemsInputTransform =
            new TransactWriteItemsInputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.transactWriteItemsOutputTransform =
            new TransactWriteItemsOutputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.scanOutputTransform =
            new ScanOutputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.queryOutputTransform =
            new QueryOutputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.batchGetItemOutputTransform =
            new BatchGetItemOutputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.executeStatementInputTransform =
            new ExecuteStatementInputTransformHandler(transformsGuard, wrapper);
        this.executeStatementOutputTransform =
            new ExecuteStatementOutputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.batchExecuteStatementInputTransform =
            new BatchExecuteStatementInputTransformHandler(transformsGuard, wrapper);
        this.batchExecuteStatementOutputTransform =
            new BatchExecuteStatementOutputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.executeTransactionInputTransform =
            new ExecuteTransactionInputTransformHandler(transformsGuard, wrapper);
        this.executeTransactionOutputTransform =
            new ExecuteTransactionOutputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.transactGetItemsInputTransform =
            new TransactGetItemsInputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.transactGetItemsOutputTransform =
            new TransactGetItemsOutputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.scanInputTransform =
            new ScanInputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.queryInputTransform =
            new QueryInputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.updateItemInputTransform =
            new UpdateItemInputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.updateItemOutputTransform =
            new UpdateItemOutputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.deleteItemInputTransform =
            new DeleteItemInputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.deleteItemOutputTransform =
            new DeleteItemOutputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.getEncryptedDataKeyDescription =
            new GetEncryptedDataKeyDescriptionHandler(wrapper, itemCodec);

        StructuredClientRegistry structuredRegistry = new StructuredClientRegistry();
        StructuredClientFactory structuredFactory = new StructuredClientFactory(factory);
        StructuredClientGuard structuredGuard = new StructuredClientGuard(structuredRegistry);
        StructuredDataCodec structuredCodec = new StructuredDataCodec();
        this.createStructuredClient = new CreateStructuredClientHandler(
            structuredRegistry, validator, structuredFactory, wrapper);
        this.encryptStructure =
            new EncryptStructureHandler(structuredGuard, wrapper, structuredCodec);
        this.decryptStructure =
            new DecryptStructureHandler(structuredGuard, wrapper, structuredCodec);
        this.encryptPathStructure =
            new EncryptPathStructureHandler(structuredGuard, wrapper, structuredCodec);
        this.decryptPathStructure =
            new DecryptPathStructureHandler(structuredGuard, wrapper, structuredCodec);
        this.resolveAuthActions =
            new ResolveAuthActionsHandler(structuredFactory, wrapper, structuredCodec);
    }

    /** @return the shared registry (for inspection in tests). */
    public ClientRegistry registry() {
        return registry;
    }

    public CreateClientHandler createClientHandler() {
        return createClient;
    }

    public EncryptItemHandler encryptItemHandler() {
        return encryptItem;
    }

    public DecryptItemHandler decryptItemHandler() {
        return decryptItem;
    }

    /**
     * Throws for an operation with no handler yet. The message names the
     * operation so a caller sees exactly which one is unimplemented.
     */
    private static <T> T notImplemented(String operation) {
        throw new UnsupportedOperationException(
            operation + " has no native-Java handler yet.");
    }

    /**
     * Build the generated service wired to these handlers. The generated
     * {@link DBESDKTestServer#builder()} is a typestate builder: every
     * operation must be added in exactly the order below (alphabetical by
     * operation name), ending with {@code build()}.
     */
    public DBESDKTestServer service() {
        return DBESDKTestServer.builder()
            .addBatchExecuteStatementInputTransformOperation(batchExecuteStatementInputTransform)
            .addBatchExecuteStatementOutputTransformOperation(batchExecuteStatementOutputTransform)
            .addBatchGetItemInputTransformOperation(batchGetItemInputTransform)
            .addBatchGetItemOutputTransformOperation(batchGetItemOutputTransform)
            .addBatchWriteItemInputTransformOperation(batchWriteItemInputTransform)
            .addBatchWriteItemOutputTransformOperation(batchWriteItemOutputTransform)
            .addCreateClientOperation(createClient)
            .addCreateStructuredClientOperation(createStructuredClient)
            .addCreateTransformsClientOperation(createTransformsClient)
            .addDecryptItemOperation(decryptItem)
            .addDecryptPathStructureOperation(decryptPathStructure)
            .addDecryptStructureOperation(decryptStructure)
            .addDeleteItemInputTransformOperation(deleteItemInputTransform)
            .addDeleteItemOutputTransformOperation(deleteItemOutputTransform)
            .addEncryptItemOperation(encryptItem)
            .addEncryptPathStructureOperation(encryptPathStructure)
            .addEncryptStructureOperation(encryptStructure)
            .addExecuteStatementInputTransformOperation(executeStatementInputTransform)
            .addExecuteStatementOutputTransformOperation(executeStatementOutputTransform)
            .addExecuteTransactionInputTransformOperation(executeTransactionInputTransform)
            .addExecuteTransactionOutputTransformOperation(executeTransactionOutputTransform)
            .addGetEncryptedDataKeyDescriptionOperation(getEncryptedDataKeyDescription)
            .addGetItemInputTransformOperation(getItemInputTransform)
            .addGetItemOutputTransformOperation(getItemOutputTransform)
            .addGetNumberOfQueriesOperation(
                (GetNumberOfQueriesOperation) (input, context) ->
                    notImplemented("GetNumberOfQueries"))
            .addPutItemInputTransformOperation(putItemInputTransform)
            .addPutItemOutputTransformOperation(putItemOutputTransform)
            .addQueryInputTransformOperation(queryInputTransform)
            .addQueryOutputTransformOperation(queryOutputTransform)
            .addResolveAuthActionsOperation(resolveAuthActions)
            .addScanInputTransformOperation(scanInputTransform)
            .addScanOutputTransformOperation(scanOutputTransform)
            .addTransactGetItemsInputTransformOperation(transactGetItemsInputTransform)
            .addTransactGetItemsOutputTransformOperation(transactGetItemsOutputTransform)
            .addTransactWriteItemsInputTransformOperation(transactWriteItemsInputTransform)
            .addTransactWriteItemsOutputTransformOperation(transactWriteItemsOutputTransform)
            .addUpdateItemInputTransformOperation(updateItemInputTransform)
            .addUpdateItemOutputTransformOperation(updateItemOutputTransform)
            .build();
    }
}
