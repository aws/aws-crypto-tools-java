package aws.cryptography.dbesdk.testserver.server.handler;

import aws.cryptography.dbesdk.testserver.server.config.ConfigValidator;
import aws.cryptography.dbesdk.testserver.server.config.ItemEncryptorFactory;
import aws.cryptography.dbesdk.testserver.server.config.TransformsClientFactory;
import aws.cryptography.dbesdk.testserver.server.error.OperationWrapper;
import aws.cryptography.dbesdk.testserver.server.registry.ClientRegistry;
import aws.cryptography.dbesdk.testserver.server.registry.TransformsClientRegistry;
import aws.cryptography.dbesdk.testserver.server.service.DBESDKTestServer;

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
 */
public final class DbesdkTestServerHandlers {

    private final ClientRegistry registry;
    private final TransformsClientRegistry transformsRegistry;
    private final CreateClientHandler createClient;
    private final EncryptItemHandler encryptItem;
    private final DecryptItemHandler decryptItem;
    private final CreateTransformsClientHandler createTransformsClient;
    private final PutItemInputTransformHandler putItemInputTransform;
    private final GetItemOutputTransformHandler getItemOutputTransform;
    private final BatchWriteItemInputTransformHandler batchWriteItemInputTransform;
    private final BatchWriteItemOutputTransformHandler batchWriteItemOutputTransform;
    private final TransactWriteItemsInputTransformHandler transactWriteItemsInputTransform;
    private final ScanOutputTransformHandler scanOutputTransform;
    private final QueryOutputTransformHandler queryOutputTransform;
    private final BatchGetItemOutputTransformHandler batchGetItemOutputTransform;
    private final ScanInputTransformHandler scanInputTransform;
    private final QueryInputTransformHandler queryInputTransform;
    private final UpdateItemInputTransformHandler updateItemInputTransform;
    private final DeleteItemInputTransformHandler deleteItemInputTransform;
    private final ExecuteStatementInputTransformHandler executeStatementInputTransform;
    private final BatchExecuteStatementInputTransformHandler batchExecuteStatementInputTransform;
    private final ExecuteTransactionInputTransformHandler executeTransactionInputTransform;

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
        this.getItemOutputTransform =
            new GetItemOutputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.batchWriteItemInputTransform =
            new BatchWriteItemInputTransformHandler(transformsGuard, wrapper, writeRequestCodec);
        this.batchWriteItemOutputTransform =
            new BatchWriteItemOutputTransformHandler(transformsGuard, wrapper, writeRequestCodec);
        this.transactWriteItemsInputTransform =
            new TransactWriteItemsInputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.scanOutputTransform =
            new ScanOutputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.queryOutputTransform =
            new QueryOutputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.batchGetItemOutputTransform =
            new BatchGetItemOutputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.executeStatementInputTransform =
            new ExecuteStatementInputTransformHandler(transformsGuard, wrapper);
        this.batchExecuteStatementInputTransform =
            new BatchExecuteStatementInputTransformHandler(transformsGuard, wrapper);
        this.executeTransactionInputTransform =
            new ExecuteTransactionInputTransformHandler(transformsGuard, wrapper);
        this.scanInputTransform =
            new ScanInputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.queryInputTransform =
            new QueryInputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.updateItemInputTransform =
            new UpdateItemInputTransformHandler(transformsGuard, wrapper, itemCodec);
        this.deleteItemInputTransform =
            new DeleteItemInputTransformHandler(transformsGuard, wrapper, itemCodec);
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

    public CreateTransformsClientHandler createTransformsClientHandler() {
        return createTransformsClient;
    }

    public PutItemInputTransformHandler putItemInputTransformHandler() {
        return putItemInputTransform;
    }

    public GetItemOutputTransformHandler getItemOutputTransformHandler() {
        return getItemOutputTransform;
    }

    public BatchWriteItemInputTransformHandler batchWriteItemInputTransformHandler() {
        return batchWriteItemInputTransform;
    }

    public TransactWriteItemsInputTransformHandler transactWriteItemsInputTransformHandler() {
        return transactWriteItemsInputTransform;
    }

    /** Build the generated service wired to these handlers. */
    public DBESDKTestServer service() {
        return DBESDKTestServer.builder()
            .addBatchExecuteStatementInputTransformOperation(batchExecuteStatementInputTransform)
            .addBatchGetItemOutputTransformOperation(batchGetItemOutputTransform)
            .addBatchWriteItemInputTransformOperation(batchWriteItemInputTransform)
            .addBatchWriteItemOutputTransformOperation(batchWriteItemOutputTransform)
            .addCreateClientOperation(createClient)
            .addCreateTransformsClientOperation(createTransformsClient)
            .addDecryptItemOperation(decryptItem)
            .addDeleteItemInputTransformOperation(deleteItemInputTransform)
            .addEncryptItemOperation(encryptItem)
            .addExecuteStatementInputTransformOperation(executeStatementInputTransform)
            .addExecuteTransactionInputTransformOperation(executeTransactionInputTransform)
            .addGetItemOutputTransformOperation(getItemOutputTransform)
            .addPutItemInputTransformOperation(putItemInputTransform)
            .addQueryInputTransformOperation(queryInputTransform)
            .addQueryOutputTransformOperation(queryOutputTransform)
            .addScanInputTransformOperation(scanInputTransform)
            .addScanOutputTransformOperation(scanOutputTransform)
            .addTransactWriteItemsInputTransformOperation(transactWriteItemsInputTransform)
            .addUpdateItemInputTransformOperation(updateItemInputTransform)
            .build();
    }
}
