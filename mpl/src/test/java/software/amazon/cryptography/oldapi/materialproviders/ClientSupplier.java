// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import java.util.Objects;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.oldapi.materialproviders.model.GetClientInput;

/**
 * Test adapter: the old wrapper type, delegating to the wrapped implementation.
 * Written for this module, not copied from the Dafny-based MPL (see MODEL_PROVENANCE.md for the copied files).
 */
public final class ClientSupplier implements IClientSupplier {

  private final IClientSupplier _impl;

  private ClientSupplier(IClientSupplier iClientSupplier) {
    this._impl = iClientSupplier;
  }

  public static <I extends IClientSupplier> ClientSupplier wrap(I iClientSupplier) {
    Objects.requireNonNull(
      iClientSupplier,
      "Missing value for required argument `iClientSupplier`"
    );
    if (iClientSupplier instanceof ClientSupplier) {
      return ((ClientSupplier) iClientSupplier);
    }
    return new ClientSupplier(iClientSupplier);
  }

  public IClientSupplier impl() {
    return this._impl;
  }

  /**
   * Returns an AWS KMS Client.
   *
   * @param input Inputs for getting a AWS KMS Client.
   *
   */
  public KmsClient GetClient(GetClientInput input) {
    return this._impl.GetClient(input);
  }
}
