// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import software.amazon.cryptography.mpl.EncryptionContext;

/** Chooses the branch key for a message from its encryption context. Must be thread-safe; a null result fails the operation with a ValidationException. */
@FunctionalInterface
public interface BranchKeyIdSupplier {
  String getBranchKeyId(EncryptionContext encryptionContext);
}
