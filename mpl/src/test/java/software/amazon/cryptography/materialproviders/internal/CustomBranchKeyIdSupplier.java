// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal;

import java.util.HashMap;
import software.amazon.cryptography.materialproviders.IBranchKeyIdSupplier;
import software.amazon.cryptography.materialproviders.model.GetBranchKeyIdInput;
import software.amazon.cryptography.mpl.keyrings.BranchKeyIdSupplier;

/**
 * Test adapter: an old-interface branch key id supplier a caller implemented, as a native supplier.
 * Its failures, and a result that cannot be read (a null output), cross the boundary as {@link Boundary#crossing} describes.
 */
public final class CustomBranchKeyIdSupplier {

  private CustomBranchKeyIdSupplier() {}

  public static BranchKeyIdSupplier of(IBranchKeyIdSupplier supplier) {
    return encryptionContext -> {
      try {
        return supplier.GetBranchKeyId(GetBranchKeyIdInput.builder().encryptionContext(new HashMap<>(encryptionContext)).build()).branchKeyId();
      } catch (RuntimeException e) {
        throw Boundary.crossing(e);
      }
    };
  }
}
