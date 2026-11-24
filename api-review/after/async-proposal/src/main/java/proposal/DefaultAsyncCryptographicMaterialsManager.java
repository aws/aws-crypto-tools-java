package proposal;

import java.util.concurrent.CompletableFuture;
import software.amazon.cryptography.materialproviders.DecryptMaterialsRequest;
import software.amazon.cryptography.materialproviders.DecryptMaterialsResponse;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsRequest;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsResponse;
import spike.AsyncKeyring;

/** Proposal: the async default CMM over an async keyring. */
public final class DefaultAsyncCryptographicMaterialsManager implements AsyncCryptographicMaterialsManager {
  private DefaultAsyncCryptographicMaterialsManager() {}

  public static DefaultAsyncCryptographicMaterialsManager create(AsyncKeyring keyring) {
    throw Stubs.stub();
  }

  @Override
  public CompletableFuture<GetEncryptionMaterialsResponse> getEncryptionMaterials(GetEncryptionMaterialsRequest request) {
    return Stubs.failed();
  }

  @Override
  public CompletableFuture<DecryptMaterialsResponse> decryptMaterials(DecryptMaterialsRequest request) {
    return Stubs.failed();
  }
}
