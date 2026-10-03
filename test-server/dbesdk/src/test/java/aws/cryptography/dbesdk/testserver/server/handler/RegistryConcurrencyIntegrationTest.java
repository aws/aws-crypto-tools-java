package aws.cryptography.dbesdk.testserver.server.handler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.dbesdk.testserver.server.model.AesWrappingAlg;
import aws.cryptography.dbesdk.testserver.server.model.CreateClientInput;
import aws.cryptography.dbesdk.testserver.server.model.CreateClientOutput;
import aws.cryptography.dbesdk.testserver.server.model.CryptoAction;
import aws.cryptography.dbesdk.testserver.server.model.CryptographicMaterialsManager;
import aws.cryptography.dbesdk.testserver.server.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.server.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.server.model.DecryptItemOutput;
import aws.cryptography.dbesdk.testserver.server.model.DefaultCmmConfig;
import aws.cryptography.dbesdk.testserver.server.model.EncryptItemInput;
import aws.cryptography.dbesdk.testserver.server.model.EncryptItemOutput;
import aws.cryptography.dbesdk.testserver.server.model.Keyring;
import aws.cryptography.dbesdk.testserver.server.model.RawAesKeyringConfig;
import aws.cryptography.dbesdk.testserver.server.registry.ClientRegistry;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

/**
 * Integration test for the thread-safe {@link ClientRegistry} under concurrency
 * (Requirement 3.3). It drives the fully-wired Java server handlers over one
 * shared registry from many threads in parallel — each thread repeatedly calls
 * {@code CreateClient} (constructing a real offline Raw-AES DBE client),
 * round-trips a DDB item through {@code EncryptItem}/{@code DecryptItem} against
 * the id it was given, and resolves that id — stressing the shared registry the
 * same way a running server's dispatch would. It asserts every minted
 * {@code ClientId} is unique, resolvable, and that no registrations are lost.
 */
class RegistryConcurrencyIntegrationTest {

    private static final DdbItemCodec ITEM_CODEC = new DdbItemCodec();
    private static final Map<String, AttributeValue> PLAINTEXT_ITEM =
        Map.of(
            "pk", AttributeValue.fromS("concurrency-partition-key"),
            "payload", AttributeValue.fromS("concurrent-round-trip-plaintext"));

    @Test
    void registryIsThreadSafeUnderConcurrentCreateAndResolve() throws Exception {
        DbesdkTestServerHandlers handlers = new DbesdkTestServerHandlers();
        ClientRegistry registry = handlers.registry();

        int threadCount = 8;
        int createsPerThread = 25;
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startGate = new CountDownLatch(1);
        List<Future<List<String>>> futures = new ArrayList<>();

        try {
            for (int t = 0; t < threadCount; t++) {
                futures.add(pool.submit(() -> {
                    startGate.await();
                    List<String> ids = new ArrayList<>();
                    for (int i = 0; i < createsPerThread; i++) {
                        CreateClientOutput created = handlers.createClientHandler().createClient(
                            CreateClientInput.builder().config(rawAesConfig()).build(), null);
                        String clientId = created.getClientId();
                        ids.add(clientId);

                        // Round-trip a DDB item against the referenced client.
                        EncryptItemOutput encrypted = handlers.encryptItemHandler().encryptItem(
                            EncryptItemInput.builder()
                                .clientId(clientId)
                                .plaintextItem(ITEM_CODEC.toModel(PLAINTEXT_ITEM))
                                .build(),
                            null);
                        DecryptItemOutput decrypted = handlers.decryptItemHandler().decryptItem(
                            DecryptItemInput.builder()
                                .clientId(clientId)
                                .encryptedItem(encrypted.getEncryptedItem())
                                .build(),
                            null);
                        assertEquals(ITEM_CODEC.toModel(PLAINTEXT_ITEM), decrypted.getPlaintextItem(),
                            "each client's item round-trip must preserve the plaintext");

                        // Concurrent resolves must always find the entry.
                        assertTrue(registry.resolve(clientId).isPresent(),
                            "a freshly registered ClientId must resolve");
                    }
                    return ids;
                }));
            }

            startGate.countDown();

            Set<String> allIds = new HashSet<>();
            List<String> collected = new ArrayList<>();
            for (Future<List<String>> future : futures) {
                collected.addAll(future.get(120, TimeUnit.SECONDS));
            }
            allIds.addAll(collected);

            int expected = threadCount * createsPerThread;
            assertEquals(expected, collected.size(),
                "every CreateClient call must have returned an id");
            assertEquals(expected, allIds.size(),
                "every minted ClientId must be unique across all threads");
            assertEquals(expected, registry.size(),
                "the registry must retain exactly one entry per successful CreateClient");
            for (String id : Collections.unmodifiableSet(allIds)) {
                assertTrue(registry.resolve(id).isPresent(),
                    "every minted ClientId must remain resolvable after the stress run");
            }
        } finally {
            pool.shutdownNow();
        }
    }

    private static DBEClientConfig rawAesConfig() {
        RawAesKeyringConfig rawAes = RawAesKeyringConfig.builder()
            .keyNamespace("concurrency-namespace")
            .keyName("concurrency-key")
            .wrappingKey(ByteBuffer.wrap(new byte[32]))
            .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
            .build();
        return DBEClientConfig.builder()
            .logicalTableName("concurrency-table")
            .partitionKeyName("pk")
            .attributeActionsOnEncrypt(Map.of(
                "pk", CryptoAction.SIGN_ONLY,
                "payload", CryptoAction.ENCRYPT_AND_SIGN))
            .cmm(CryptographicMaterialsManager.builder()
                .defaultMember(DefaultCmmConfig.builder()
                    .keyring(Keyring.builder().rawAes(rawAes).build())
                    .build())
                .build())
            .build();
    }
}
