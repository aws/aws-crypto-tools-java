// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

/**
 * Creates one KMS client per Region on first request and reuses it; an empty Region means the SDK's default Region.
 * Thread-safe; {@link #close()} closes the clients.
 */
public final class DefaultClientSupplier implements ClientSupplier, AutoCloseable {

  DefaultClientSupplier() {}

  /**
   * {@inheritDoc}
   *
   * @throws ValidationException if {@code region} is empty and the SDK finds no default Region
   */
  @Override
  public synchronized KmsClient getClient(String region) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  @Override
  public synchronized void close() {
    throw new UnsupportedOperationException("not implemented yet");
  }
}
