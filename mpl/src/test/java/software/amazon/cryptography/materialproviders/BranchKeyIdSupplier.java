// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import java.util.Objects;
import software.amazon.cryptography.materialproviders.model.GetBranchKeyIdInput;
import software.amazon.cryptography.materialproviders.model.GetBranchKeyIdOutput;

/**
 * Test adapter: the old wrapper type, delegating to the wrapped implementation.
 * Written for this module, not copied from the Dafny-based MPL (see MODEL_PROVENANCE.md for the copied files).
 */
public final class BranchKeyIdSupplier implements IBranchKeyIdSupplier {

  private final IBranchKeyIdSupplier _impl;

  private BranchKeyIdSupplier(IBranchKeyIdSupplier iBranchKeyIdSupplier) {
    this._impl = iBranchKeyIdSupplier;
  }

  public static <I extends IBranchKeyIdSupplier> BranchKeyIdSupplier wrap(I iBranchKeyIdSupplier) {
    Objects.requireNonNull(
      iBranchKeyIdSupplier,
      "Missing value for required argument `iBranchKeyIdSupplier`"
    );
    if (iBranchKeyIdSupplier instanceof BranchKeyIdSupplier) {
      return ((BranchKeyIdSupplier) iBranchKeyIdSupplier);
    }
    return new BranchKeyIdSupplier(iBranchKeyIdSupplier);
  }

  /**
   * Given the Encryption Context associated with this encryption or decryption, returns the branch key that should be responsible for unwrapping or wrapping the data key.
   *
   * @param input Inputs for determining the Branch Key which should be used to wrap or unwrap the data key for this encryption or decryption
   * @return Outputs for the Branch Key responsible for wrapping or unwrapping the data key in this encryption or decryption.
   */
  public GetBranchKeyIdOutput GetBranchKeyId(GetBranchKeyIdInput input) {
    return this._impl.GetBranchKeyId(input);
  }
}
