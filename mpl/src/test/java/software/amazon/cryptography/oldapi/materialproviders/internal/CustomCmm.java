// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders.internal;

import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.DecryptMaterialsRequest;
import software.amazon.cryptography.materialproviders.DecryptMaterialsResponse;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsRequest;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsResponse;
import software.amazon.cryptography.materialproviders.internal.MaterialsAccess;
import software.amazon.cryptography.oldapi.materialproviders.ICryptographicMaterialsManager;

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
    if (cmm instanceof software.amazon.cryptography.oldapi.materialproviders.CryptographicMaterialsManager) {
      return of(((software.amazon.cryptography.oldapi.materialproviders.CryptographicMaterialsManager) cmm).impl());
    }
    if (cmm instanceof NativeCmm) {
      return ((NativeCmm) cmm).cmm();
    }
    return new CustomCmm(cmm);
  }

  @Override
  public GetEncryptionMaterialsResponse getEncryptionMaterials(GetEncryptionMaterialsRequest request) {
    try {
      software.amazon.cryptography.oldapi.materialproviders.model.EncryptionMaterials output = cmm
        .GetEncryptionMaterials(Requests.input(request))
        .encryptionMaterials();
      Boundary.encryptionMaterials(output);
      return GetEncryptionMaterialsResponse.builder().encryptionMaterials(MaterialsAccess.encryption(Convert.fields(output))).build();
    } catch (RuntimeException e) {
      throw Boundary.crossing(e);
    }
  }

  @Override
  public DecryptMaterialsResponse decryptMaterials(DecryptMaterialsRequest request) {
    try {
      software.amazon.cryptography.oldapi.materialproviders.model.DecryptionMaterials output = cmm
        .DecryptMaterials(Requests.input(request))
        .decryptionMaterials();
      Boundary.decryptionMaterials(output);
      return DecryptMaterialsResponse.builder().decryptionMaterials(MaterialsAccess.decryption(Convert.fields(output))).build();
    } catch (RuntimeException e) {
      throw Boundary.crossing(e);
    }
  }
}
