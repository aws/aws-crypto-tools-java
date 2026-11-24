package proposal;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnDecryptResponse;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;
import software.amazon.cryptography.materialproviders.cache.CryptographicMaterialsCache;
import spike.AsyncKeyring;

/** Proposal: the async hierarchical keyring, over any async key store. */
public final class AwsKmsHierarchicalAsyncKeyring implements AsyncKeyring {
  private AwsKmsHierarchicalAsyncKeyring() {}

  public static Builder builder() {
    return new Builder();
  }

  @Override
  public CompletableFuture<OnEncryptResponse> onEncrypt(OnEncryptRequest request) {
    return Stubs.failed();
  }

  @Override
  public CompletableFuture<OnDecryptResponse> onDecrypt(OnDecryptRequest request) {
    return Stubs.failed();
  }

  public static final class Builder {
    private Builder() {}

    public Builder keyStore(AsyncKeyStore keyStore) {
      return this;
    }

    public Builder branchKeyId(String branchKeyId) {
      return this;
    }

    public Builder branchKeyIdSupplier(AsyncBranchKeyIdSupplier branchKeyIdSupplier) {
      return this;
    }

    public Builder ttl(Duration ttl) {
      return this;
    }

    public Builder cache(CryptographicMaterialsCache cache) {
      return this;
    }

    public Builder partitionId(String partitionId) {
      return this;
    }

    public AwsKmsHierarchicalAsyncKeyring build() {
      throw Stubs.stub();
    }
  }
}
