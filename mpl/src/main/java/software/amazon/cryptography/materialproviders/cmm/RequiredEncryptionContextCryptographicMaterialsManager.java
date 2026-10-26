// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.cmm;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.DecryptMaterialsRequest;
import software.amazon.cryptography.materialproviders.DecryptMaterialsResponse;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsRequest;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsResponse;
import software.amazon.cryptography.materialproviders.exceptions.EncryptionContextMismatchException;
import software.amazon.cryptography.materialproviders.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.internal.MaterialsAccess;
import software.amazon.cryptography.materialproviders.internal.MaterialsRules;

/**
 * Wraps another manager and requires that the given encryption context keys are present on encrypt
 * and supplied again on decrypt. Those keys are authenticated but not stored in the message.
 * The underlying manager's results are checked.
 * Thread-safe if the underlying manager is.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/required-encryption-context-cmm.md">Required Encryption Context CMM</a>.
 */
// The Dafny-based MPL skipped the result checks for its own managers, whose results were proven valid;
// those checks always pass for the built-in managers here.
public final class RequiredEncryptionContextCryptographicMaterialsManager implements CryptographicMaterialsManager {

  private final CryptographicMaterialsManager underlyingCmm;
  private final List<String> requiredEncryptionContextKeys;

  private RequiredEncryptionContextCryptographicMaterialsManager(Builder builder) {
    this.underlyingCmm = builder.underlyingCmm;
    this.requiredEncryptionContextKeys = Collections.unmodifiableList(new ArrayList<>(builder.requiredEncryptionContextKeys));
  }

  public static Builder builder() {
    return new Builder();
  }

  public CryptographicMaterialsManager underlyingCmm() {
    return underlyingCmm;
  }

  /** Without duplicates, in the order first given. */
  public List<String> requiredEncryptionContextKeys() {
    return requiredEncryptionContextKeys;
  }

  @Override
  public GetEncryptionMaterialsResponse getEncryptionMaterials(GetEncryptionMaterialsRequest request) {
    //= spec/framework/required-encryption-context-cmm.md#get-encryption-materials
    //# The encryption context on the [encryption materials request](./cmm-interface.md#encryption-materials-request)
    //# MUST contain a value for every key in the configured [required encryption context keys](#required-encryption-context-keys)
    //# or this request MUST fail.
    if (!request.encryptionContext().keySet().containsAll(requiredEncryptionContextKeys)) {
      throw new ValidationException("Encryption context does not contain required keys.");
    }
    //= spec/framework/required-encryption-context-cmm.md#get-encryption-materials
    //# All configured [required encryption context keys](#required-encryption-context-keys)
    //# MUST exist in the required encryption context keys
    //# of the [encryption materials request](./cmm-interface.md#encryption-materials-request)
    //# to the [underlying CMM's](#underlying-cryptographic-materials-manager).
    List<String> keys = new ArrayList<>(request.requiredEncryptionContextKeys());
    keys.addAll(requiredEncryptionContextKeys);
    //= spec/framework/required-encryption-context-cmm.md#get-encryption-materials
    //# The Required Encryption Context CMM MUST attempt to obtain [encryption materials](./structures.md#encryption-materials)
    //# by making a call to the [underlying CMM's](#underlying-cryptographic-materials-manager)
    //# [Get Encryption Materials](cmm-interface.md#get-encryption-materials).
    EncryptionMaterials result = underlyingCmm.getEncryptionMaterials(request.toBuilder().requiredEncryptionContextKeys(keys).build()).encryptionMaterials();
    //= spec/framework/required-encryption-context-cmm.md#get-encryption-materials
    //# The obtained [encryption materials](./structures.md#encryption-materials) MUST
    //# have all configured [required encryption context keys](#required-encryption-context-keys)
    //# in it's [required encryption context keys](./structures.md#required-encryption-context-keys).
    if (!result.requiredEncryptionContextKeys().containsAll(requiredEncryptionContextKeys)) {
      throw new InvalidMaterialsException("Expected encryption context keys do not exist in keys to only authenticate.");
    }
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
    if (!MaterialsRules.isReadyForEncrypt(MaterialsAccess.fields(result))) {
      throw new InvalidMaterialsException("Could not retrieve materials required for encryption");
    }
    //= spec/framework/cmm-interface.md#get-encryption-materials
    //# - The [Required Encryption Context Keys](structures.md#required-encryption-context-keys) MUST be
    //#   a super set of the Required Encryption Context Keys in the [encryption materials request](#encryption-materials-request).
    if (!result.requiredEncryptionContextKeys().containsAll(request.requiredEncryptionContextKeys())) {
      throw new InvalidMaterialsException("Keyring returned an invalid response");
    }
    return GetEncryptionMaterialsResponse.builder().encryptionMaterials(result).build();
  }

  /**
   * {@inheritDoc}
   *
   * @throws EncryptionContextMismatchException if a reproduced value differs from the stored value of the same key
   * @throws ValidationException if the reproduced context is absent or lacks a required key
   */
  @Override
  public DecryptMaterialsResponse decryptMaterials(DecryptMaterialsRequest request) {
    if (!request.reproducedEncryptionContext().isPresent()) {
      throw new ValidationException("No reproduced encryption context on decrypt.");
    }
    EncryptionContext reproduced = request.reproducedEncryptionContext().get();
    EncryptionContext stored = request.encryptionContext();
    for (Map.Entry<String, String> entry : reproduced.entrySet()) {
      //= spec/framework/cmm-interface.md#decrypt-materials
      //# The CMM MUST validate the [Encryption Context](structures.md#encryption-context)
      //# by comparing it to the customer supplied [Reproduced Encryption Context](structures.md#encryption-context)
      //# in [decrypt materials request](#decrypt-materials-request).
      //# For every key that exists in both [Reproduced Encryption Context](structures.md#encryption-context)
      //# and [Encryption Context](structures.md#encryption-context),
      //# the values MUST be equal or the operation MUST fail.
      if (stored.containsKey(entry.getKey()) && !stored.get(entry.getKey()).equals(entry.getValue())) {
        throw new EncryptionContextMismatchException("Encryption context does not match reproduced encryption context.");
      }
    }
    //= spec/framework/required-encryption-context-cmm.md#decrypt-materials
    //# The reproduced encryption context on the [decrypt materials request](./cmm-interface.md#decrypt-materials-request)
    //# MUST contain a value for every key in the configured [required encryption context keys](#required-encryption-context-keys)
    //# or this request MUST fail.
    if (!reproduced.keySet().containsAll(requiredEncryptionContextKeys)) {
      throw new ValidationException("Reproduced encryption context missing required keys.");
    }
    //= spec/framework/required-encryption-context-cmm.md#decrypt-materials
    //# The Required Encryption Context
    //# CMM MUST attempt to obtain [decryption materials](./structures.md#decryption-materials)
    //# by making a call to the [underlying CMM's](#underlying-cryptographic-materials-manager)
    //# [decrypt materials](cmm-interface.md#decrypt-materials) interface
    //# with the unchanged [decrypt materials request](./cmm-interface.md#decrypt-materials-request).
    DecryptionMaterials result = underlyingCmm.decryptMaterials(request).decryptionMaterials();
    EncryptionContext finalContext = result.encryptionContext();
    //= spec/framework/required-encryption-context-cmm.md#decrypt-materials
    //# The obtained [decryption materials](./structures.md#decryption-materials) MUST
    //# have all configured [required encryption context keys](#required-encryption-context-keys)
    //# in it's [encryption context](./structures.md#encryption-context-2).
    if (!finalContext.keySet().containsAll(requiredEncryptionContextKeys)) {
      throw new InvalidMaterialsException("Final encryption context missing required keys.");
    }
    //= spec/framework/cmm-interface.md#decrypt-materials
    //# - All key-value pairs that exist in [Reproduced Encryption Context](structures.md#encryption-context)
    //# but do not exist in encryption context on the [decrypt materials request](#decrypt-materials-request)
    //# SHOULD be appended to the decryption materials.
    if (!finalContext.entrySet().containsAll(reproduced.entrySet())) {
      throw new InvalidMaterialsException("Reproduced encryption context missing from encryption context.");
    }
    //= spec/framework/cmm-interface.md#decrypt-materials
    //# The decryption materials returned MUST include the following:
    //
    //= spec/framework/cmm-interface.md#decrypt-materials
    //# The CMM MUST ensure that the decryption materials returned are valid.
    //# - The decryption materials returned MUST follow the specification for [decryption-materials](structures.md#decryption-materials).
    //# - The value of the plaintext data key MUST be non-NULL.
    if (!MaterialsRules.isReadyForDecrypt(MaterialsAccess.fields(result))) {
      throw new InvalidMaterialsException("Keyring.OnDecrypt failed to decrypt the plaintext data key.");
    }
    return DecryptMaterialsResponse.builder().decryptionMaterials(result).build();
  }

  /**
   * Not thread-safe.
   * {@link #build()} throws {@link ValidationException} without an underlying manager or a required key.
   */
  public static final class Builder {

    private CryptographicMaterialsManager underlyingCmm;
    private Collection<String> requiredEncryptionContextKeys = new LinkedHashSet<>();

    private Builder() {}

    public Builder underlyingCmm(CryptographicMaterialsManager underlyingCmm) {
      this.underlyingCmm = underlyingCmm;
      return this;
    }

    /** Duplicates are dropped. Copied. */
    public Builder requiredEncryptionContextKeys(Collection<String> keys) {
      this.requiredEncryptionContextKeys = new LinkedHashSet<>(keys);
      for (String key : this.requiredEncryptionContextKeys) {
        Objects.requireNonNull(key, "required encryption context key");
      }
      return this;
    }

    /** The same as {@link #requiredEncryptionContextKeys(Collection)} with these values; a null array is passed on as a null collection. */
    public Builder requiredEncryptionContextKeys(String... keys) {
      return requiredEncryptionContextKeys(keys == null ? null : Arrays.asList(keys));
    }

    public RequiredEncryptionContextCryptographicMaterialsManager build() {
      if (underlyingCmm == null) {
        throw new ValidationException("CreateRequiredEncryptionContextCMM currently only supports cmm.");
      }
      if (requiredEncryptionContextKeys.isEmpty()) {
        throw new ValidationException("RequiredEncryptionContextCMM needs at least one requiredEncryptionContextKey.");
      }
      return new RequiredEncryptionContextCryptographicMaterialsManager(this);
    }
  }
}
