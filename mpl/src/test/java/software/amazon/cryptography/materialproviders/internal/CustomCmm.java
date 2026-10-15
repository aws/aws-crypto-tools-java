// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal;

import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.mpl.CryptographicMaterialsManager;
import software.amazon.cryptography.mpl.DecryptMaterialsRequest;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.GetEncryptionMaterialsRequest;
import software.amazon.cryptography.mpl.internal.MaterialsAccess;

/**
 * Test adapter: an old-interface materials manager a caller implemented, as a native one.
 * Its results are taken as returned, valid or not, so the native checks see them.
 */
public final class CustomCmm implements CryptographicMaterialsManager {

  private final ICryptographicMaterialsManager cmm;

  private CustomCmm(ICryptographicMaterialsManager cmm) {
    this.cmm = cmm;
  }

  /** The native manager behind an old-interface manager. */
  public static CryptographicMaterialsManager of(ICryptographicMaterialsManager cmm) {
    if (cmm instanceof software.amazon.cryptography.materialproviders.CryptographicMaterialsManager) {
      return of(((software.amazon.cryptography.materialproviders.CryptographicMaterialsManager) cmm).impl());
    }
    if (cmm instanceof NativeCmm) {
      return ((NativeCmm) cmm).cmm();
    }
    return new CustomCmm(cmm);
  }

  @Override
  public EncryptionMaterials getEncryptionMaterials(GetEncryptionMaterialsRequest request) {
    try {
      software.amazon.cryptography.materialproviders.model.EncryptionMaterials output = cmm
        .GetEncryptionMaterials(Requests.input(request))
        .encryptionMaterials();
      Boundary.encryptionMaterials(output);
      return MaterialsAccess.encryption(Convert.fields(output));
    } catch (RuntimeException e) {
      throw Boundary.crossing(e);
    }
  }

  @Override
  public DecryptionMaterials decryptMaterials(DecryptMaterialsRequest request) {
    try {
      software.amazon.cryptography.materialproviders.model.DecryptionMaterials output = cmm
        .DecryptMaterials(Requests.input(request))
        .decryptionMaterials();
      Boundary.decryptionMaterials(output);
      return MaterialsAccess.decryption(Convert.fields(output));
    } catch (RuntimeException e) {
      throw Boundary.crossing(e);
    }
  }
}
