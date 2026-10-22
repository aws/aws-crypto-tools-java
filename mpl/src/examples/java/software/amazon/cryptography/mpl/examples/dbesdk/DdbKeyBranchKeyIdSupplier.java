// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples.dbesdk;

import java.util.Map;
import software.amazon.cryptography.mpl.keyrings.BranchKeyIdSupplier;
import software.amazon.cryptography.mpl.keyrings.GetBranchKeyIdResponse;

/**
 * STAND-IN for the DB-ESDK's {@code IDynamoDbKeyBranchKeyIdSupplier}: chooses a branch key from an item's primary key.
 *
 * <p>Customers implement this (often as a lambda) and the DB-ESDK adapts it to the MPL's {@link BranchKeyIdSupplier}
 * with {@link #asBranchKeyIdSupplier}, as {@code CreateDynamoDbEncryptionBranchKeyIdSupplier} does today.
 * The adapter reads the key back from the encryption context the item encryptor wrote, so it only understands
 * {@link DbEsdkLikeItemEncryptor}'s context layout: string-typed partition and sort keys.
 */
@FunctionalInterface
public interface DdbKeyBranchKeyIdSupplier {
  /** @param ddbKey the item's partition key and, if the table has one, sort key, by attribute name */
  String branchKeyId(Map<String, String> ddbKey);

  /** The MPL supplier that decodes the primary key from the encryption context and asks {@code supplier}. */
  static BranchKeyIdSupplier asBranchKeyIdSupplier(DdbKeyBranchKeyIdSupplier supplier) {
    return request -> GetBranchKeyIdResponse.builder()
      .branchKeyId(supplier.branchKeyId(DbEsdkLikeItemEncryptor.ddbKey(request.encryptionContext())))
      .build();
  }
}
