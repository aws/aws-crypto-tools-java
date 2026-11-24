package spike;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;
import software.amazon.cryptography.materialproviders.SecretBytes;

/** Runs the spike against the stub client. No AWS calls. */
public final class SpikeMain {
  private static final String KEY = "arn:aws:kms:us-west-2:111122223333:key/spike";

  public static void main(String[] args) throws Exception {
    StubKmsAsyncClient kms = new StubKmsAsyncClient(50);
    AsyncKeyring keyring = AwsKmsAsyncKeyring.builder().kmsKeyId(KEY).kmsClient(kms).build();
    AlgorithmSuite suite = EsdkAlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;

    // 1. Round trip; the returned future is not done when onEncrypt returns: the caller thread is free.
    EncryptionMaterials start = EncryptionMaterials.builder(suite).build();
    keyring.onEncrypt(OnEncryptRequest.builder().materials(start).build()).join(); // warm up class loading
    long t0 = System.nanoTime();
    CompletableFuture<OnEncryptResponse> pending = keyring.onEncrypt(OnEncryptRequest.builder().materials(start).build());
    long returnedMicros = (System.nanoTime() - t0) / 1000;
    boolean doneAtReturn = pending.isDone();
    String[] completedOn = new String[1];
    EncryptionMaterials encrypted = pending.thenApply(r -> {
      completedOn[0] = Thread.currentThread().getName();
      return r.materials();
    }).get(5, TimeUnit.SECONDS);
    System.out.println("1. onEncrypt returned in " + returnedMicros + " us (stub KMS latency 50 ms), done at return=" + doneAtReturn + "; completed on " + completedOn[0]
        + "; EDKs=" + encrypted.encryptedDataKeys().size());

    DecryptionMaterials dm = DecryptionMaterials.builder(suite).build();
    DecryptionMaterials decrypted = keyring.onDecrypt(OnDecryptRequest.builder().materials(dm)
        .encryptedDataKeys(encrypted.encryptedDataKeys()).build()).get(5, TimeUnit.SECONDS).materials();
    boolean same = java.util.Arrays.equals(decrypted.plaintextDataKey().get().toByteArray(),
        encrypted.plaintextDataKey().get().toByteArray());
    System.out.println("   onDecrypt recovered the same data key: " + same);

    // 2. Failures arrive through the future, as the MPL's exception types (the SDK error is the cause chain).
    CompletableFuture<?> bad = keyring.onDecrypt(OnDecryptRequest.builder().materials(dm)
        .encryptedDataKeys(software.amazon.cryptography.materialproviders.EncryptedDataKey.builder().keyProviderId("aws-kms")
            .keyProviderInfo(KEY.getBytes("UTF-8")).ciphertext(new byte[48]).build()).build());
    try {
      bad.join();
    } catch (RuntimeException e) {
      Throwable cause = Futures.unwrap(e);
      System.out.println("2. bad EDK -> " + cause.getClass().getSimpleName() + " (inner: "
          + ((software.amazon.cryptography.materialproviders.exceptions.NoMatchingDataKeyException) cause).failures().get(0).getClass().getSimpleName() + ")");
    }

    // 3. Adapters: a pure-CPU sync keyring runs inline; a blocking one needs an explicit executor.
    Keyring rawAes = RawAesKeyring.builder().keyNamespace("ns").keyName("name")
        .wrappingKey(SecretBytes.random(32)).wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16).build();
    AsyncKeyring inline = AsyncKeyrings.fromNonBlocking(rawAes);
    System.out.println("3. raw AES via fromNonBlocking: done at return = "
        + inline.onEncrypt(OnEncryptRequest.builder().materials(start).build()).isDone());
    ExecutorService blockingPool = Executors.newFixedThreadPool(4);
    AsyncKeyring offloaded = AsyncKeyrings.fromBlocking(rawAes, blockingPool);
    System.out.println("   raw AES via fromBlocking: EDKs = "
        + offloaded.onEncrypt(OnEncryptRequest.builder().materials(start).build()).get(5, TimeUnit.SECONDS).materials().encryptedDataKeys().size());

    // 4. Storm tracking without parked threads: 200 concurrent cold reads of one key, one fetch.
    ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    ExecutorService completion = Executors.newFixedThreadPool(2);
    AsyncStormTracker<String, String> cache = new AsyncStormTracker<>(10_000, 1_000, 10_000, 20, 20,
        System::currentTimeMillis, scheduler, completion);
    AtomicInteger fetches = new AtomicInteger();
    int peakThreadsBefore = Thread.activeCount();
    CompletableFuture<?>[] all = new CompletableFuture<?>[200];
    for (int i = 0; i < all.length; i++) {
      all[i] = cache.get("branch-key").thenCompose((Optional<String> hit) -> {
        if (hit.isPresent()) {
          return CompletableFuture.completedFuture(hit.get());
        }
        fetches.incrementAndGet();
        // The fetch: an async key store read. Here, the stub KMS call stands in for DynamoDB + KMS.
        return kms.generateDataKey(b -> b.keyId(KEY).numberOfBytes(32)).thenApply(r -> {
          cache.put("branch-key", "materials", System.currentTimeMillis() + 60_000);
          return "materials";
        });
      });
    }
    CompletableFuture.allOf(all).get(5, TimeUnit.SECONDS);
    System.out.println("4. 200 concurrent cold gets -> fetches=" + fetches.get()
        + ", threads before=" + peakThreadsBefore + " after=" + Thread.activeCount() + " (no thread per waiter)");

    // 5. The caller example: a round trip through the async keyring.
    System.out.println("5. caller example round trip: " + AsyncCallerExample.kmsRoundTrip(kms, KEY).get(5, TimeUnit.SECONDS)
        + "; adapters: " + AsyncCallerExample.adapt(rawAes, rawAes, blockingPool).length);

    blockingPool.shutdown();
    scheduler.shutdown();
    completion.shutdown();
    kms.close();
  }
}
