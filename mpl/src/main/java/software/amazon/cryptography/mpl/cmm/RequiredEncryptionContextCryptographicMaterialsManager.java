// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.cmm;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import software.amazon.cryptography.mpl.CryptographicMaterialsManager;
import software.amazon.cryptography.mpl.DecryptMaterialsRequest;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.GetEncryptionMaterialsRequest;
import software.amazon.cryptography.mpl.exceptions.EncryptionContextMismatchException;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

/**
 * Wraps another manager and requires that the given encryption context keys are present on encrypt
 * and supplied again on decrypt. Those keys are authenticated but not stored in the message.
 * The underlying manager's results are checked.
 * Thread-safe if the underlying manager is.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/required-encryption-context-cmm.md">Required Encryption Context CMM</a>.
 */
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
  public EncryptionMaterials getEncryptionMaterials(GetEncryptionMaterialsRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /**
   * {@inheritDoc}
   *
   * @throws EncryptionContextMismatchException if a reproduced value differs from the stored value of the same key
   * @throws ValidationException if the reproduced context is absent or lacks a required key
   */
  @Override
  public DecryptionMaterials decryptMaterials(DecryptMaterialsRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
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
