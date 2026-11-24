package proposal;

import java.util.concurrent.CompletableFuture;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.cryptography.materialproviders.keystore.GetActiveBranchKeyRequest;
import software.amazon.cryptography.materialproviders.keystore.GetActiveBranchKeyResponse;
import software.amazon.cryptography.materialproviders.keystore.GetBeaconKeyRequest;
import software.amazon.cryptography.materialproviders.keystore.GetBeaconKeyResponse;
import software.amazon.cryptography.materialproviders.keystore.GetBranchKeyVersionRequest;
import software.amazon.cryptography.materialproviders.keystore.GetBranchKeyVersionResponse;
import software.amazon.cryptography.materialproviders.keystore.GetKeyStoreInfoRequest;
import software.amazon.cryptography.materialproviders.keystore.GetKeyStoreInfoResponse;
import software.amazon.cryptography.materialproviders.keystore.KmsConfiguration;

/** Proposal: the async DynamoDB key store, with the sync key store's builder members, requests, and responses. */
public final class AsyncDynamoDbKeyStore implements AsyncKeyStore {
  private AsyncDynamoDbKeyStore() {}

  public static Builder builder() {
    return new Builder();
  }

  @Override
  public CompletableFuture<GetActiveBranchKeyResponse> getActiveBranchKey(GetActiveBranchKeyRequest request) {
    return Stubs.failed();
  }

  @Override
  public CompletableFuture<GetBranchKeyVersionResponse> getBranchKeyVersion(GetBranchKeyVersionRequest request) {
    return Stubs.failed();
  }

  @Override
  public CompletableFuture<GetBeaconKeyResponse> getBeaconKey(GetBeaconKeyRequest request) {
    return Stubs.failed();
  }

  @Override
  public CompletableFuture<GetKeyStoreInfoResponse> getKeyStoreInfo(GetKeyStoreInfoRequest request) {
    return Stubs.failed();
  }

  public static final class Builder {
    private Builder() {}

    public Builder ddbTableName(String ddbTableName) {
      return this;
    }

    public Builder logicalKeyStoreName(String logicalKeyStoreName) {
      return this;
    }

    public Builder kmsConfiguration(KmsConfiguration kmsConfiguration) {
      return this;
    }

    public Builder ddbClient(DynamoDbAsyncClient ddbClient) {
      return this;
    }

    public Builder kmsClient(KmsAsyncClient kmsClient) {
      return this;
    }

    public AsyncDynamoDbKeyStore build() {
      throw Stubs.stub();
    }
  }
}
