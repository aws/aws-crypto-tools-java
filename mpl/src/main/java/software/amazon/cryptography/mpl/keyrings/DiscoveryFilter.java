// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

/** Restricts discovery keyrings to KMS keys in the given AWS accounts of one partition. Immutable. */
public final class DiscoveryFilter {

  private final List<String> accountIds;
  private final String partition;

  private DiscoveryFilter(List<String> accountIds, String partition) {
    this.accountIds = accountIds;
    this.partition = partition;
  }

  /**
   * @param accountIds at least one; each non-empty
   * @param partition non-empty, for example {@code aws}
   * @throws ValidationException if a list or string is empty
   */
  public static DiscoveryFilter of(Collection<String> accountIds, String partition) {
    List<String> accounts = Collections.unmodifiableList(new ArrayList<>(accountIds));
    accounts.forEach(Objects::requireNonNull);
    Objects.requireNonNull(partition, "partition");
    if (accounts.isEmpty()) {
      throw new ValidationException("Discovery filter must have at least one account ID");
    }
    if (accounts.contains("")) {
      throw new ValidationException("Discovery filter account IDs cannot be blank");
    }
    if (partition.isEmpty()) {
      throw new ValidationException("Discovery filter partition cannot be blank");
    }
    return new DiscoveryFilter(accounts, partition);
  }

  public List<String> accountIds() {
    return accountIds;
  }

  public String partition() {
    return partition;
  }

  /** Whether a key in {@code partition} and {@code account} passes the filter. */
  boolean matches(String keyPartition, String keyAccount) {
    return partition.equals(keyPartition) && accountIds.contains(keyAccount);
  }

  @Override
  public boolean equals(Object other) {
    if (!(other instanceof DiscoveryFilter)) {
      return false;
    }
    DiscoveryFilter that = (DiscoveryFilter) other;
    return accountIds.equals(that.accountIds) && partition.equals(that.partition);
  }

  @Override
  public int hashCode() {
    return Objects.hash(accountIds, partition);
  }

  /** Partition and account ids. */
  @Override
  public String toString() {
    return "DiscoveryFilter{partition=" + partition + ", accountIds=" + accountIds + "}";
  }
}
