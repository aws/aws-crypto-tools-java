// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders.internal;

import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.oldapi.materialproviders.ClientSupplier;
import software.amazon.cryptography.oldapi.materialproviders.IClientSupplier;
import software.amazon.cryptography.oldapi.materialproviders.model.GetClientInput;

/** Test adapter: an old-interface client supplier as a native one, and a native one behind the old interface. */
public final class CustomClientSupplier {

  private CustomClientSupplier() {}

  /** The native supplier behind an old-interface supplier; a caller's exception crosses as the old API wrapped it. */
  public static software.amazon.cryptography.mpl.keyrings.ClientSupplier of(IClientSupplier supplier) {
    if (supplier instanceof ClientSupplier) {
      return of(((ClientSupplier) supplier).impl());
    }
    if (supplier instanceof Native) {
      return ((Native) supplier).supplier;
    }
    return region -> {
      try {
        return supplier.GetClient(GetClientInput.builder().region(region).build());
      } catch (RuntimeException e) {
        throw Boundary.crossing(e);
      }
    };
  }

  /** A native supplier behind the old interface. */
  public static IClientSupplier toOld(software.amazon.cryptography.mpl.keyrings.ClientSupplier supplier) {
    return new Native(supplier);
  }

  private static final class Native implements IClientSupplier {

    final software.amazon.cryptography.mpl.keyrings.ClientSupplier supplier;

    Native(software.amazon.cryptography.mpl.keyrings.ClientSupplier supplier) {
      this.supplier = supplier;
    }

    @Override
    public KmsClient GetClient(GetClientInput input) {
      try {
        return supplier.getClient(input.region());
      } catch (RuntimeException e) {
        throw Errors.toOld(e);
      }
    }
  }
}
