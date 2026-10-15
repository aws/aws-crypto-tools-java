// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import java.util.Objects;
import software.amazon.cryptography.materialproviders.model.DecryptMaterialsInput;
import software.amazon.cryptography.materialproviders.model.DecryptMaterialsOutput;
import software.amazon.cryptography.materialproviders.model.GetEncryptionMaterialsInput;
import software.amazon.cryptography.materialproviders.model.GetEncryptionMaterialsOutput;

/**
 * Test adapter: the old wrapper type, delegating to the wrapped implementation.
 * Written for this module, not copied from the Dafny-based MPL (see MODEL_PROVENANCE.md for the copied files).
 */
public final class CryptographicMaterialsManager implements ICryptographicMaterialsManager {

  private final ICryptographicMaterialsManager _impl;

  private CryptographicMaterialsManager(ICryptographicMaterialsManager iCryptographicMaterialsManager) {
    this._impl = iCryptographicMaterialsManager;
  }

  public static <I extends ICryptographicMaterialsManager> CryptographicMaterialsManager wrap(I iCryptographicMaterialsManager) {
    Objects.requireNonNull(
      iCryptographicMaterialsManager,
      "Missing value for required argument `iCryptographicMaterialsManager`"
    );
    if (iCryptographicMaterialsManager instanceof CryptographicMaterialsManager) {
      return ((CryptographicMaterialsManager) iCryptographicMaterialsManager);
    }
    return new CryptographicMaterialsManager(iCryptographicMaterialsManager);
  }

  public ICryptographicMaterialsManager impl() {
    return this._impl;
  }

  public DecryptMaterialsOutput DecryptMaterials(DecryptMaterialsInput input) {
    return this._impl.DecryptMaterials(input);
  }

  public GetEncryptionMaterialsOutput GetEncryptionMaterials(GetEncryptionMaterialsInput input) {
    return this._impl.GetEncryptionMaterials(input);
  }
}
