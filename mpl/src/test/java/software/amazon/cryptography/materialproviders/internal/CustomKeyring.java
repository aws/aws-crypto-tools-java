// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal;

import java.util.ArrayList;
import java.util.List;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.model.OnDecryptInput;
import software.amazon.cryptography.materialproviders.model.OnEncryptInput;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnDecryptResponse;
import software.amazon.cryptography.mpl.OnEncryptRequest;
import software.amazon.cryptography.mpl.OnEncryptResponse;
import software.amazon.cryptography.mpl.internal.MaterialsAccess;

/**
 * Test adapter: an old-interface keyring a caller implemented, as a native keyring.
 * Its results are taken as returned, valid or not, so the native checks see them; like the Dafny-based MPL's
 * boundary, a result that cannot be converted (a string that is not UTF-8) fails as an exception from the keyring.
 */
public final class CustomKeyring implements Keyring {

  private final IKeyring keyring;

  private CustomKeyring(IKeyring keyring) {
    this.keyring = keyring;
  }

  /** The native keyring behind an old-interface keyring. */
  public static Keyring of(IKeyring keyring) {
    if (keyring instanceof software.amazon.cryptography.materialproviders.Keyring) {
      return of(((software.amazon.cryptography.materialproviders.Keyring) keyring).impl());
    }
    if (keyring instanceof NativeKeyring) {
      return ((NativeKeyring) keyring).keyring();
    }
    return new CustomKeyring(keyring);
  }

  @Override
  public OnEncryptResponse onEncrypt(OnEncryptRequest request) {
    OnEncryptInput input = OnEncryptInput.builder().materials(Convert.materials(request.materials())).build();
    try {
      software.amazon.cryptography.materialproviders.model.EncryptionMaterials output = keyring.OnEncrypt(input).materials();
      Boundary.encryptionMaterials(output);
      return OnEncryptResponse.builder().materials(MaterialsAccess.encryption(Convert.fields(output))).build();
    } catch (RuntimeException e) {
      throw Boundary.crossing(e);
    }
  }

  @Override
  public OnDecryptResponse onDecrypt(OnDecryptRequest request) {
    List<EncryptedDataKey> edks = new ArrayList<>();
    for (software.amazon.cryptography.mpl.EncryptedDataKey edk : request.encryptedDataKeys()) {
      edks.add(Convert.edk(edk));
    }
    OnDecryptInput input = OnDecryptInput.builder().materials(Convert.materials(request.materials())).encryptedDataKeys(edks).build();
    try {
      software.amazon.cryptography.materialproviders.model.DecryptionMaterials output = keyring.OnDecrypt(input).materials();
      Boundary.decryptionMaterials(output);
      return OnDecryptResponse.builder().materials(MaterialsAccess.decryption(Convert.fields(output))).build();
    } catch (RuntimeException e) {
      throw Boundary.crossing(e);
    }
  }
}
