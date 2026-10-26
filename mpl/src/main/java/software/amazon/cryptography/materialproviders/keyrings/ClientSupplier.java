// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keyrings;

import software.amazon.awssdk.services.kms.KmsClient;

/** Supplies the KMS client for a Region to the multi-Region and multi-key KMS keyrings. Must be thread-safe. */
@FunctionalInterface
public interface ClientSupplier {
  /**
   * The client for {@code region}; an empty Region means the SDK's default Region.
   * The multi keyrings ask for {@code ""} for a KMS key given as a key id or alias name rather than an ARN,
   * so with {@link #defaultSupplier()} that key is used in the SDK's default Region.
   */
  KmsClient getClient(String region);

  /**
   * A supplier that creates one default-configured client per Region on first use and reuses it.
   * Close it to close the clients it created.
   */
  static DefaultClientSupplier defaultSupplier() {
    return new DefaultClientSupplier();
  }
}
