package proposal;

import java.util.concurrent.CompletableFuture;
import software.amazon.cryptography.materialproviders.keyrings.BranchKeyIdSupplier;
import software.amazon.cryptography.materialproviders.keyrings.GetBranchKeyIdRequest;
import software.amazon.cryptography.materialproviders.keyrings.GetBranchKeyIdResponse;

/** Proposal: the async branch key id supplier; one method, so a lambda works. */
public interface AsyncBranchKeyIdSupplier {
  CompletableFuture<GetBranchKeyIdResponse> getBranchKeyId(GetBranchKeyIdRequest request);

  static AsyncBranchKeyIdSupplier fromNonBlocking(BranchKeyIdSupplier supplier) {
    throw Stubs.stub();
  }
}
