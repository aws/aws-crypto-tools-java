package proposal;

import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import software.amazon.cryptography.materialproviders.keystore.GetActiveBranchKeyRequest;
import software.amazon.cryptography.materialproviders.keystore.GetActiveBranchKeyResponse;
import software.amazon.cryptography.materialproviders.keystore.GetBeaconKeyRequest;
import software.amazon.cryptography.materialproviders.keystore.GetBeaconKeyResponse;
import software.amazon.cryptography.materialproviders.keystore.GetBranchKeyVersionRequest;
import software.amazon.cryptography.materialproviders.keystore.GetBranchKeyVersionResponse;
import software.amazon.cryptography.materialproviders.keystore.GetKeyStoreInfoRequest;
import software.amazon.cryptography.materialproviders.keystore.GetKeyStoreInfoResponse;

/** Proposal: the async twin of KeyStore, with the same reads and default overloads, returning futures. */
public interface AsyncKeyStore {
  CompletableFuture<GetActiveBranchKeyResponse> getActiveBranchKey(GetActiveBranchKeyRequest request);

  default CompletableFuture<GetActiveBranchKeyResponse> getActiveBranchKey(
      Consumer<GetActiveBranchKeyRequest.Builder> request) {
    GetActiveBranchKeyRequest.Builder builder = GetActiveBranchKeyRequest.builder();
    request.accept(builder);
    return getActiveBranchKey(builder.build());
  }

  CompletableFuture<GetBranchKeyVersionResponse> getBranchKeyVersion(GetBranchKeyVersionRequest request);

  default CompletableFuture<GetBranchKeyVersionResponse> getBranchKeyVersion(Consumer<GetBranchKeyVersionRequest.Builder> request) {
    GetBranchKeyVersionRequest.Builder builder = GetBranchKeyVersionRequest.builder();
    request.accept(builder);
    return getBranchKeyVersion(builder.build());
  }

  CompletableFuture<GetBeaconKeyResponse> getBeaconKey(GetBeaconKeyRequest request);

  default CompletableFuture<GetBeaconKeyResponse> getBeaconKey(Consumer<GetBeaconKeyRequest.Builder> request) {
    GetBeaconKeyRequest.Builder builder = GetBeaconKeyRequest.builder();
    request.accept(builder);
    return getBeaconKey(builder.build());
  }

  CompletableFuture<GetKeyStoreInfoResponse> getKeyStoreInfo(GetKeyStoreInfoRequest request);

  default CompletableFuture<GetKeyStoreInfoResponse> getKeyStoreInfo(Consumer<GetKeyStoreInfoRequest.Builder> request) {
    GetKeyStoreInfoRequest.Builder builder = GetKeyStoreInfoRequest.builder();
    request.accept(builder);
    return getKeyStoreInfo(builder.build());
  }

  default CompletableFuture<GetKeyStoreInfoResponse> getKeyStoreInfo() {
    return getKeyStoreInfo(GetKeyStoreInfoRequest.builder().build());
  }
}
