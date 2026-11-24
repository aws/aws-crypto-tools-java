package proposal;

import software.amazon.awssdk.services.kms.KmsClient;

/** Proposal: ClientSupplier renamed before 2.0.0, so that the async one can be KmsAsyncClientSupplier. */
public interface KmsClientSupplier {
  KmsClient getClient(String region);
}
