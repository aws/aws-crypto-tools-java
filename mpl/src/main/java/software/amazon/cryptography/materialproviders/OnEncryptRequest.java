// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

/**
 * Input to {@link Keyring#onEncrypt}. Immutable.
 * Holds the caller's materials, not a copy; they stay with the caller.
 */
public final class OnEncryptRequest {

  private final EncryptionMaterials materials;

  private OnEncryptRequest(Builder builder) {
    this.materials = builder.materials;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this request's values. */
  public Builder toBuilder() {
    return new Builder().materials(materials);
  }

  /** The materials to add this keyring's encrypted data key to. */
  public EncryptionMaterials materials() {
    return materials;
  }

  @Override
  public String toString() {
    return "OnEncryptRequest[" + materials + "]";
  }

  /** Not thread-safe. Requires materials. */
  public static final class Builder {

    private EncryptionMaterials materials;

    private Builder() {}

    public Builder materials(EncryptionMaterials materials) {
      this.materials = materials;
      return this;
    }

    public OnEncryptRequest build() {
      if (materials == null) {
        throw new ValidationException("Missing value for required field `materials`");
      }
      return new OnEncryptRequest(this);
    }
  }
}
