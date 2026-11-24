// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package software.amazon.cryptography.esdk;

import java.util.Map;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.Keyring;

/** Checks the request builders share. */
final class Requests {

  private Requests() {}

  static void requireOneMaterialSource(
      final Keyring keyring, final CryptographicMaterialsManager materialsManager) {
    if ((keyring == null) == (materialsManager == null)) {
      throw new EsdkValidationException("Exactly one of `keyring` or `materialsManager` is required");
    }
  }

  static void requirePositiveFrameLength(final Integer frameLength) {
    if (frameLength != null && frameLength < 1) {
      throw new EsdkValidationException("frameLength must be positive");
    }
  }

  static EncryptionContext encryptionContext(final Map<String, String> encryptionContext) {
    return encryptionContext == null
        ? EncryptionContext.empty()
        : EncryptionContext.copyOf(encryptionContext);
  }
}
