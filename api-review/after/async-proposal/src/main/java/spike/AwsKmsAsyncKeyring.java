package spike;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnDecryptResponse;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;
import software.amazon.cryptography.materialproviders.exceptions.NoMatchingDataKeyException;

/**
 * The KMS keyring over {@link KmsAsyncClient}: the async twin of AwsKmsKeyring, with the same builder
 * members except the client type, and the same request/response types.
 *
 * <p>Never blocks: each KMS call is {@code kms.xxx(request)} followed by {@code thenApply(check)}.
 * The check runs on whichever thread completes the SDK future (the SDK's future-completion executor
 * by default), which is fine: it is a few comparisons and an array copy.
 */
public final class AwsKmsAsyncKeyring implements AsyncKeyring {
  private final String kmsKeyId;
  private final KmsAsyncClient kmsClient;
  private final List<String> grantTokens;

  private AwsKmsAsyncKeyring(Builder b) {
    this.kmsKeyId = b.kmsKeyId;
    this.kmsClient = b.kmsClient;
    this.grantTokens = Collections.unmodifiableList(new ArrayList<>(b.grantTokens));
  }

  public static Builder builder() {
    return new Builder();
  }

  public String kmsKeyId() {
    return kmsKeyId;
  }

  public KmsAsyncClient kmsClient() {
    return kmsClient;
  }

  @Override
  public CompletableFuture<OnEncryptResponse> onEncrypt(OnEncryptRequest request) {
    return Futures.guard(() -> {
      EncryptionMaterials m = request.materials();
      if (!m.plaintextDataKey().isPresent()) {
        return kmsClient.generateDataKey(KmsSteps.generateDataKey(kmsKeyId, m, grantTokens))
            .thenApply(r -> OnEncryptResponse.builder().materials(KmsSteps.afterGenerate(kmsKeyId, m, r)).build());
      }
      return kmsClient.encrypt(KmsSteps.encrypt(kmsKeyId, m, grantTokens))
          .thenApply(r -> OnEncryptResponse.builder().materials(KmsSteps.afterEncrypt(m, r)).build());
    });
  }

  @Override
  public CompletableFuture<OnDecryptResponse> onDecrypt(OnDecryptRequest request) {
    return Futures.guard(() -> {
      DecryptionMaterials m = request.materials();
      List<EncryptedDataKey> candidates = new ArrayList<>();
      for (EncryptedDataKey edk : request.encryptedDataKeys()) {
        if (KmsSteps.matches(kmsKeyId, edk)) {
          candidates.add(edk);
        }
      }
      // Sequential, as the sync keyring: try the next EDK only after the previous one failed.
      return tryFrom(m, candidates, 0, new ArrayList<>());
    });
  }

  private CompletableFuture<OnDecryptResponse> tryFrom(DecryptionMaterials m, List<EncryptedDataKey> edks, int i, List<Throwable> errors) {
    if (i == edks.size()) {
      return Futures.failed(new NoMatchingDataKeyException("Unable to decrypt any data key", errors));
    }
    CompletableFuture<OnDecryptResponse> attempt = kmsClient.decrypt(KmsSteps.decrypt(kmsKeyId, m, edks.get(i), grantTokens))
        .thenApply(r -> OnDecryptResponse.builder().materials(KmsSteps.afterDecrypt(kmsKeyId, m, r)).build());
    return Futures.recoverWith(attempt, t -> {
      errors.add(t);
      return tryFrom(m, edks, i + 1, errors);
    });
  }

  public static final class Builder {
    private String kmsKeyId;
    private KmsAsyncClient kmsClient;
    private List<String> grantTokens = Collections.emptyList();

    private Builder() {}

    public Builder kmsKeyId(String kmsKeyId) {
      this.kmsKeyId = kmsKeyId;
      return this;
    }

    public Builder kmsClient(KmsAsyncClient kmsClient) {
      this.kmsClient = kmsClient;
      return this;
    }

    public Builder grantTokens(List<String> grantTokens) {
      this.grantTokens = Objects.requireNonNull(grantTokens);
      return this;
    }

    public AwsKmsAsyncKeyring build() {
      Objects.requireNonNull(kmsKeyId, "kmsKeyId");
      Objects.requireNonNull(kmsClient, "kmsClient");
      return new AwsKmsAsyncKeyring(this);
    }
  }
}
