// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import java.util.Objects;
import software.amazon.cryptography.materialproviders.model.OnDecryptInput;
import software.amazon.cryptography.materialproviders.model.OnDecryptOutput;
import software.amazon.cryptography.materialproviders.model.OnEncryptInput;
import software.amazon.cryptography.materialproviders.model.OnEncryptOutput;

/**
 * Test adapter: the old wrapper type, delegating to the wrapped implementation.
 * Written for this module, not copied from the Dafny-based MPL (see MODEL_PROVENANCE.md for the copied files).
 */
public final class Keyring implements IKeyring {

  private final IKeyring _impl;

  private Keyring(IKeyring iKeyring) {
    this._impl = iKeyring;
  }

  public static <I extends IKeyring> Keyring wrap(I iKeyring) {
    Objects.requireNonNull(
      iKeyring,
      "Missing value for required argument `iKeyring`"
    );
    if (iKeyring instanceof Keyring) {
      return ((Keyring) iKeyring);
    }
    return new Keyring(iKeyring);
  }

  public IKeyring impl() {
    return this._impl;
  }

  public OnDecryptOutput OnDecrypt(OnDecryptInput input) {
    return this._impl.OnDecrypt(input);
  }

  public OnEncryptOutput OnEncrypt(OnEncryptInput input) {
    return this._impl.OnEncrypt(input);
  }
}
