// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal;

import java.util.HashMap;
import software.amazon.cryptography.materialproviders.IBranchKeyIdSupplier;
import software.amazon.cryptography.materialproviders.model.GetBranchKeyIdInput;
import software.amazon.cryptography.mpl.keyrings.BranchKeyIdSupplier;
import software.amazon.cryptography.mpl.keyrings.GetBranchKeyIdResponse;

/**
 * Test adapter: an old-interface branch key id supplier a caller implemented, as a native supplier.
 * Its failures, and a result that cannot be read (a null output), cross the boundary as {@link Boundary#crossing} describes.
 */
public final class CustomBranchKeyIdSupplier {

  private CustomBranchKeyIdSupplier() {}

  public static BranchKeyIdSupplier of(IBranchKeyIdSupplier supplier) {
    return request -> {
      try {
        String id = supplier
          .GetBranchKeyId(GetBranchKeyIdInput.builder().encryptionContext(new HashMap<>(request.encryptionContext())).build())
          .branchKeyId();
        // A null id reaches the keyring as a null response, which it reports as the Dafny-based keyring did.
        return id == null ? null : GetBranchKeyIdResponse.builder().branchKeyId(id).build();
      } catch (RuntimeException e) {
        throw Boundary.crossing(e);
      }
    };
  }
}
