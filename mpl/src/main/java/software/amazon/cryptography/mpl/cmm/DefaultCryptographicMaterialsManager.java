// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.cmm;

import java.util.Objects;
import software.amazon.cryptography.mpl.CryptographicMaterialsManager;
import software.amazon.cryptography.mpl.DecryptMaterialsRequest;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.GetEncryptionMaterialsRequest;
import software.amazon.cryptography.mpl.Keyring;

//= spec/framework/default-cmm.md#legacy
//= type=implication
//# Master key providers SHOULD NOT be included in any additional implementations.
//
//= spec/framework/default-cmm.md#initialization-1
//= type=implication
//# In place of requiring the caller to provide a [keyring](keyring-interface.md)
//# on initialization:
//#
//# On default CMM initialization,
//# the caller MUST provide the following value:
//#
//# - [Master Key Provider](master-key-provider-interface.md)
//
//= spec/framework/default-cmm.md#get-encryption-materials-master-key-provider
//= type=implication
//# In place of calling its keyring's [On Encrypt](keyring-interface.md#onencrypt) operation:
//#
//# The default CMM MUST call its master key provider's
//# [Get Master Keys for Encryption](master-key-provider-interface.md#get-master-keys-for-encryption) operation
//# to obtain a list of master keys to use.
//#
//# If the master key provider does not identify which master key MUST generate the data key,
//# the default CMM MUST use the first master key in the list for that purpose.
//# The default CMM MUST generate the data key using this master key's
//# [Generate Data Key](master-key-interface.md#generate-data-key) operation.
//#
//# For each remaining master key,
//# the default CMM MUST call the master key's
//# [Encrypt Data Key](master-key-interface.md#encrypt-data-key) operation
//# with the plaintext data key.
//
//= spec/framework/default-cmm.md#decrypt-materials-master-key-provider
//= type=implication
//# In place of calling its keyring's [On Decrypt](keyring-interface.md#ondecrypt) operation:
//#
//# The default CMM MUST call its master key provider's
//# [Decrypt Data Key](master-key-provider-interface.md#decrypt-data-key) operation.
/**
 * Gets data keys from one keyring: picks the suite (the request's, or the policy's default),
 * generates the signing key pair for signing suites, and checks the result against the commitment policy.
 * Thread-safe.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/default-cmm.md">Default CMM</a>.
 */
public final class DefaultCryptographicMaterialsManager implements CryptographicMaterialsManager {

  private final Keyring keyring;

  private DefaultCryptographicMaterialsManager(Keyring keyring) {
    this.keyring = keyring;
  }

  public static DefaultCryptographicMaterialsManager of(Keyring keyring) {
    //= spec/framework/default-cmm.md#initialization
    //= type=implication
    //# On default CMM initialization,
    //# the caller MUST provide the following value:
    //# - [Keyring](#keyring)
    return new DefaultCryptographicMaterialsManager(Objects.requireNonNull(keyring, "keyring"));
  }

  public Keyring keyring() {
    return keyring;
  }

  @Override
  public EncryptionMaterials getEncryptionMaterials(GetEncryptionMaterialsRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /**
   * {@inheritDoc}
   *
   * <p>Reproduced context keys missing from the stored context become required keys of the result, in UTF-8 byte order.
   *
   * @throws software.amazon.cryptography.mpl.exceptions.EncryptionContextMismatchException
   *   if a reproduced value differs from the stored value of the same key
   */
  @Override
  public DecryptionMaterials decryptMaterials(DecryptMaterialsRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }
}
