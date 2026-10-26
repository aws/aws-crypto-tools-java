// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keyrings;

/**
 * Chooses the branch key for a message from its encryption context. Must be thread-safe.
 * A null response fails the operation with a {@link software.amazon.cryptography.materialproviders.exceptions.ValidationException};
 * an exception the supplier throws reaches the caller unchanged.
 */
@FunctionalInterface
public interface BranchKeyIdSupplier {
  GetBranchKeyIdResponse getBranchKeyId(GetBranchKeyIdRequest request);
}
