// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.cmm;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import software.amazon.cryptography.mpl.AlgorithmSuite;
import software.amazon.cryptography.mpl.CryptographicMaterialsManager;
import software.amazon.cryptography.mpl.DecryptMaterialsRequest;
import software.amazon.cryptography.mpl.DecryptMaterialsResponse;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptionContext;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.GetEncryptionMaterialsRequest;
import software.amazon.cryptography.mpl.GetEncryptionMaterialsResponse;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnEncryptRequest;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.SecretBytes;
import software.amazon.cryptography.mpl.exceptions.EncryptionContextMismatchException;
import software.amazon.cryptography.mpl.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.CommitmentChecks;
import software.amazon.cryptography.mpl.internal.MaterialsAccess;
import software.amazon.cryptography.mpl.internal.MaterialsRules;
import software.amazon.cryptography.mpl.internal.primitives.Bytes;
import software.amazon.cryptography.mpl.internal.primitives.Ecdsa;

//= spec/framework/default-cmm.md#legacy-behavior-master-key-providers
//= type=exception
//= reason=Master key providers are not part of this library, so this default CMM uses keyrings only.
//# For implementations that support [master key providers](master-key-provider-interface.md),
//# the default CMM MUST support generating, encrypting, and decrypting data keys
//# using master key providers.
//
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

  //= spec/framework/cmm-interface.md#get-encryption-materials
  //= type=exception
  //= reason=Whether the materials suit the request depends on the keyring, which this CMM cannot verify.
  //# When the CMM gets an [encryption materials request](#encryption-materials-request),
  //# it MUST return [encryption materials](structures.md#encryption-materials) appropriate for the request.
  //
  //= spec/framework/cmm-interface.md#get-encryption-materials
  //= type=exception
  //= reason=Whether each encrypted data key decrypts to the plaintext data key depends on the keyring, which this CMM cannot verify.
  //# - Every encrypted data key in this list MUST correspond to the above plaintext data key.
  @Override
  public GetEncryptionMaterialsResponse getEncryptionMaterials(GetEncryptionMaterialsRequest request) {
    //= spec/framework/default-cmm.md#get-encryption-materials
    //# If the encryption context included in the [encryption materials request](cmm-interface.md#encryption-materials-request)
    //# already contains the `aws-crypto-public-key` key,
    //# this operation MUST fail rather than overwrite the associated value.
    if (request.encryptionContext().containsKey(MaterialsRules.EC_PUBLIC_KEY_FIELD)) {
      throw new ValidationException("Reserved Field found in EncryptionContext keys.");
    }
    //= spec/framework/default-cmm.md#get-encryption-materials
    //# - If the [encryption materials request](cmm-interface.md#encryption-
    //# materials-request) does contain an algorithm suite, the encryption
    //# materials returned MUST contain the same algorithm suite.
    //
    //= spec/framework/default-cmm.md#get-encryption-materials
    //# - If the [encryption materials request](cmm-interface.md#encryption-
    //# materials-request) does not contain an algorithm suite, the
    //# operation MUST add the default algorithm suite for the [commitment
    //# policy](./commitment-policy.md#supported-commitment-policy-enum) as the
    //# algorithm suite in the encryption materials returned.
    //= spec/framework/cmm-interface.md#get-encryption-materials
    //# - If the encryption materials request contains an algorithm suite, the encryption materials returned
    //# SHOULD contain the same algorithm suite.
    AlgorithmSuite suite = request.algorithmSuiteId().orElse(request.commitmentPolicy().defaultSuite());
    //= spec/framework/default-cmm.md#get-encryption-materials
    //# - If the [encryption materials request](cmm-interface.md#encryption-
    //# materials-request) does contain an algorithm suite, the request
    //# MUST fail if the algorithm suite is not supported by the
    //# [commitment policy](./commitment-policy.md#supported-commitment-policy-enum) on
    //# the request.
    CommitmentChecks.requireEncrypt(request.commitmentPolicy(), suite);
    EncryptionMaterials.Builder builder = EncryptionMaterials
      .builder(suite)
      .encryptionContext(request.encryptionContext())
      .requiredEncryptionContextKeys(request.requiredEncryptionContextKeys());
    //= spec/framework/cmm-interface.md#get-encryption-materials
    //# If the algorithm suite contains a [signing algorithm](algorithm-suites.md#signature-algorithm):
    //#
    //# - The CMM MUST include a [signing key](structures.md#signing-key).
    //# - The CMM SHOULD also add a key-value pair using the reserved key `aws-crypto-public-key` to the encryption context.
    //#   If it does, the mapped value SHOULD be the signature verification key corresponding to the signing key.
    //#
    //# If the algorithm suite does not contain a [signing algorithm](algorithm-suites.md#signature-algorithm):
    //#
    //# - The CMM SHOULD NOT add a key-value pair using the reserved key `aws-crypto-public-key` to the encryption context.
    //
    //= spec/framework/cmm-interface.md#get-encryption-materials
    //= type=implication
    //# - The CMM MAY modify the encryption context.
    if (suite.signature().isPresent()) {
      //= spec/framework/default-cmm.md#get-encryption-materials
      //# If the algorithm suite contains a [signing algorithm](algorithm-suites.md#signature-algorithm),
      //# the default CMM MUST Generate a [signing key](structures.md#signing-key).
      byte[][] pair = Ecdsa.generateKeyPair(suite.signature().get());
      SecretBytes signingKey = SecretBytes.copyOf(pair[1]);
      Bytes.zero(pair[1]);
      builder.signingKeyPair(signingKey, pair[0]);
      signingKey.destroy();
    }
    EncryptionMaterials materials = builder.build();
    //= spec/framework/default-cmm.md#get-encryption-materials
    //# On each call to Get Encryption Materials,
    //# the default CMM MUST make a call to its [keyring's](#keyring)
    //# [On Encrypt](keyring-interface.md#onencrypt) operation.
    EncryptionMaterials result = keyring.onEncrypt(OnEncryptRequest.builder().materials(materials).build()).materials();
    MaterialsRules.Encryption fields = MaterialsAccess.fields(result);
    //= spec/framework/cmm-interface.md#get-encryption-materials
    //# The encryption materials returned MUST include the following:
    //
    //= spec/framework/cmm-interface.md#get-encryption-materials
    //# The CMM MUST ensure that the encryption materials returned are valid.
    //# - The encryption materials returned MUST follow the specification for [encryption-materials](structures.md#encryption-materials).
    //# - The value of the plaintext data key MUST be non-NULL.
    //# - The plaintext data key length MUST be equal to the [key derivation input length](algorithm-suites.md#key-derivation-input-length).
    //# - The encrypted data keys list MUST contain at least one encrypted data key.
    //# - If the algorithm suite contains a signing algorithm, the encryption materials returned MUST include the generated signing key.
    //# - For every key in [Required Encryption Context Keys](structures.md#required-encryption-context-keys)
    //#   there MUST be a matching key in the [Encryption Context](structures.md#encryption-context-1).
    if (!MaterialsRules.isReadyForEncrypt(fields)) {
      throw new InvalidMaterialsException("Could not retrieve materials required for encryption");
    }
    //= spec/framework/cmm-interface.md#get-encryption-materials
    //= type=implication
    //# - The [Required Encryption Context Keys](structures.md#required-encryption-context-keys) MUST be
    //#   a super set of the Required Encryption Context Keys in the [encryption materials request](#encryption-materials-request).
    if (!MaterialsRules.isValidTransition(MaterialsAccess.fields(materials), fields)) {
      throw new InvalidMaterialsException("Keyring returned an invalid response");
    }
    //= spec/framework/default-cmm.md#get-encryption-materials
    //= type=implication
    //# The default CMM MUST obtain the Plaintext Data Key from the
    //# On Encrypt Response and include it in the
    //# [encryption materials](structures.md#encryption-materials) returned.
    //
    //= spec/framework/default-cmm.md#get-encryption-materials
    //= type=implication
    //# The default CMM MUST obtain the
    //# [Encrypted Data Keys](structures.md#encrypted-data-keys)
    //# from the On Encrypt Response and include it
    //# in the [encryption materials](structures.md#encryption-materials) returned.
    return GetEncryptionMaterialsResponse.of(result);
  }

  //= spec/framework/cmm-interface.md#decrypt-materials
  //= type=exception
  //= reason=Whether the materials suit the request depends on the keyring, which this CMM cannot verify.
  //# When the CMM gets a [decrypt materials request](#decrypt-materials-request),
  //# it MUST return [decryption materials](structures.md#decryption-materials) appropriate for the request.
  //
  //= spec/framework/cmm-interface.md#decrypt-materials
  //= type=exception
  //= reason=This is a permission, not an obligation this CMM can be checked against.
  //# - The CMM MAY modify the encryption context.
  //
  //= spec/framework/cmm-interface.md#decrypt-materials
  //= type=exception
  //= reason=Whether the plaintext data key matches an encrypted data key depends on the keyring, which this CMM cannot verify.
  //# - The plaintext data key returned MUST correspond with at least one of the encrypted data keys.
  //
  //= spec/framework/cmm-interface.md#decrypt-materials
  //= type=exception
  //= reason=This is a requirement of intent on custom CMMs; this CMM's only change to the context is the public key it adds and later reads back.
  //# - The operations made on the encryption context on the Get Encryption Materials call
  //# SHOULD be inverted on the Decrypt Materials call.
  /**
   * {@inheritDoc}
   *
   * <p>Reproduced context keys missing from the stored context become required keys of the result, in UTF-8 byte order.
   *
   * @throws software.amazon.cryptography.mpl.exceptions.EncryptionContextMismatchException
   *   if a reproduced value differs from the stored value of the same key
   */
  @Override
  public DecryptMaterialsResponse decryptMaterials(DecryptMaterialsRequest request) {
    //= spec/framework/default-cmm.md#decrypt-materials
    //# The request MUST fail if the algorithm suite on the request is not
    //# supported by the [commitment policy](./commitment-policy.md#supported-commitment-policy-enum)
    //# on the request.
    CommitmentChecks.requireDecrypt(request.commitmentPolicy(), request.algorithmSuiteId());
    EncryptionContext stored = request.encryptionContext();
    EncryptionContext merged = stored;
    List<String> requiredKeys = new ArrayList<>();
    if (request.reproducedEncryptionContext().isPresent()) {
      // EncryptionContext iterates in UTF-8 byte order.
      for (Map.Entry<String, String> entry : request.reproducedEncryptionContext().get().entrySet()) {
        String key = entry.getKey();
        if (stored.containsKey(key)) {
          //= spec/framework/cmm-interface.md#decrypt-materials
          //# The CMM MUST validate the [Encryption Context](structures.md#encryption-context)
          //# by comparing it to the customer supplied [Reproduced Encryption Context](structures.md#encryption-context)
          //# in [decrypt materials request](#decrypt-materials-request).
          //# For every key that exists in both [Reproduced Encryption Context](structures.md#encryption-context)
          //# and [Encryption Context](structures.md#encryption-context),
          //# the values MUST be equal or the operation MUST fail.
          if (!stored.get(key).equals(entry.getValue())) {
            throw new EncryptionContextMismatchException("Encryption context does not match reproduced encryption context.");
          }
        } else {
          //= spec/framework/cmm-interface.md#decrypt-materials
          //# - This set MUST include all keys added to the decryption materials encryption context
          //# that existed in the [decrypt materials request's](#decrypt-materials-request) reproduced encryption context
          //# but did not exist in the [decrypt materials request's](#decrypt-materials-request) encryption context.
          requiredKeys.add(key);
          //= spec/framework/cmm-interface.md#decrypt-materials
          //# - All key-value pairs that exist in [Reproduced Encryption Context](structures.md#encryption-context)
          //# but do not exist in encryption context on the [decrypt materials request](#decrypt-materials-request)
          //# SHOULD be appended to the decryption materials.
          merged = merged.with(key, entry.getValue());
        }
      }
    }
    //= spec/framework/cmm-interface.md#decrypt-materials
    //# - If the decrypt materials request contains an algorithm suite,
    //# the decryption materials returned SHOULD contain the same algorithm suite.
    //
    //= spec/framework/cmm-interface.md#decrypt-materials
    //= type=implication
    //# If the algorithm suite obtained from the decryption request contains a [signing algorithm](algorithm-suites.md#signature-algorithm),
    //# the decryption materials MUST include the [signature verification key](structures.md#verification-key).
    DecryptionMaterials materials = DecryptionMaterials
      .builder(request.algorithmSuiteId())
      .encryptionContext(merged)
      .requiredEncryptionContextKeys(requiredKeys)
      .build();
    //= spec/framework/default-cmm.md#decrypt-materials
    //# On each call to Decrypt Materials,
    //# the default CMM MUST make a call to its [keyring's](#keyring)
    //# [On Decrypt](keyring-interface.md#ondecrypt) operation.
    DecryptionMaterials result = keyring.onDecrypt(OnDecryptRequest.builder().materials(materials).encryptedDataKeys(request.encryptedDataKeys()).build()).materials();
    //= spec/framework/cmm-interface.md#decrypt-materials
    //# The decryption materials returned MUST include the following:
    //
    //= spec/framework/cmm-interface.md#decrypt-materials
    //# The CMM MUST ensure that the decryption materials returned are valid.
    //# - The decryption materials returned MUST follow the specification for [decryption-materials](structures.md#decryption-materials).
    //# - The value of the plaintext data key MUST be non-NULL.
    if (!MaterialsRules.isValidTransition(MaterialsAccess.fields(materials), MaterialsAccess.fields(result))) {
      throw new InvalidMaterialsException("Keyring.OnDecrypt failed to decrypt the plaintext data key.");
    }
    //= spec/framework/default-cmm.md#decrypt-materials
    //= type=implication
    //# The default CMM MUST obtain the Plaintext Data Key from
    //# the On Decrypt response and include it in the decrypt
    //# materials returned.
    return DecryptMaterialsResponse.of(result);
  }
}
