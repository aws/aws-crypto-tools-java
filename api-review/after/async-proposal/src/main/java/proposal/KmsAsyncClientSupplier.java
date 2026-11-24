package proposal;

import software.amazon.awssdk.services.kms.KmsAsyncClient;

/** Proposal: the async client supplier, named after a renamed KmsClientSupplier. */
public interface KmsAsyncClientSupplier {
  KmsAsyncClient getClient(String region);
}
