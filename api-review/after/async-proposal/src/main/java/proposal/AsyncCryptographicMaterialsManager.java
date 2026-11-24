package proposal;

import java.util.concurrent.CompletableFuture;
import software.amazon.cryptography.materialproviders.DecryptMaterialsRequest;
import software.amazon.cryptography.materialproviders.DecryptMaterialsResponse;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsRequest;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsResponse;

/** Proposal: the async CMM, with the sync CMM's requests and responses. */
public interface AsyncCryptographicMaterialsManager {
  CompletableFuture<GetEncryptionMaterialsResponse> getEncryptionMaterials(GetEncryptionMaterialsRequest request);

  CompletableFuture<DecryptMaterialsResponse> decryptMaterials(DecryptMaterialsRequest request);
}
