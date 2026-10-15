// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;
import software.amazon.cryptography.mpl.internal.UserAgent;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

/**
 * Creates one KMS client per Region on first request and reuses it; an empty Region means the SDK's default Region.
 * Thread-safe; {@link #close()} closes the clients.
 */
public final class DefaultClientSupplier implements ClientSupplier, AutoCloseable {

  // Guarded by this, so close() cannot miss a client getClient is creating.
  private final Map<String, KmsClient> clients = new HashMap<>();

  DefaultClientSupplier() {}

  /**
   * {@inheritDoc}
   *
   * @throws ValidationException if {@code region} is empty and the SDK finds no default Region
   */
  @Override
  public synchronized KmsClient getClient(String region) {
    Objects.requireNonNull(region, "region");
    return clients.computeIfAbsent(region, DefaultClientSupplier::create);
  }

  @Override
  public synchronized void close() {
    List<KmsClient> created = new ArrayList<>(clients.values());
    clients.clear();
    for (KmsClient client : created) {
      client.close();
    }
  }

  private static KmsClient create(String region) {
    KmsClientBuilder builder = KmsClient
      .builder()
      .overrideConfiguration(UserAgent.overrideConfiguration());
    if (!region.isEmpty()) {
      builder.region(Region.of(region));
    }
    try {
      return builder.build();
    } catch (SdkClientException e) {
      throw new ValidationException(e.getMessage(), e);
    }
  }
}
