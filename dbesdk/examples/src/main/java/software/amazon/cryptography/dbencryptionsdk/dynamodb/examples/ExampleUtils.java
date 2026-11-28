// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples;

import java.util.concurrent.ThreadLocalRandom;

/**
 * Shared utilities for the examples.
 *
 * <p>Each example writes items under a fixed partition key name such as "rawEcdhKeyringItem". If
 * several runs of the examples use the same table at the same time, one run can overwrite another
 * run's item, and the other run then fails to decrypt what it reads back. {@link
 * #uniquePartitionKey(String)} appends a random suffix chosen once per JVM, so each run writes its
 * own items (for example "rawEcdhKeyringItem-482913").
 */
public final class ExampleUtils {

  private static final String RUN_SUFFIX = String.valueOf(
    ThreadLocalRandom.current().nextInt(100000, 999999)
  );

  private ExampleUtils() {}

  /**
   * Returns a partition key value unique to this JVM process. Example: "rawEcdhKeyringItem" becomes
   * "rawEcdhKeyringItem-482913"
   */
  public static String uniquePartitionKey(String baseName) {
    return baseName + runSuffix();
  }

  /**
   * Returns the suffix uniquePartitionKey appends in this JVM process, such as "-482913". Queries
   * that read several items can filter on it, for example {@code contains(partition_key, :suffix)},
   * so they see only the items this run wrote.
   */
  public static String runSuffix() {
    return "-" + RUN_SUFFIX;
  }
}
