// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl;

import software.amazon.cryptography.mpl.exceptions.ValidationException;

/**
 * Output of {@link Keyring#onEncrypt}. Immutable.
 * Holds the materials, not a copy; whoever receives the response owns them.
 */
public final class OnEncryptResponse {

  private final EncryptionMaterials materials;

  private OnEncryptResponse(Builder builder) {
    this.materials = builder.materials;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** The same as {@code builder().materials(materials).build()}. */
  public static OnEncryptResponse of(EncryptionMaterials materials) {
    return builder().materials(materials).build();
  }

  /** A builder holding this response's values. */
  public Builder toBuilder() {
    return new Builder().materials(materials);
  }

  /** The request's materials with a plaintext data key and this keyring's encrypted copy of it added. */
  public EncryptionMaterials materials() {
    return materials;
  }

  @Override
  public String toString() {
    return "OnEncryptResponse[" + materials + "]";
  }

  /** Not thread-safe. Requires materials. */
  public static final class Builder {

    private EncryptionMaterials materials;

    private Builder() {}

    public Builder materials(EncryptionMaterials materials) {
      this.materials = materials;
      return this;
    }

    public OnEncryptResponse build() {
      if (materials == null) {
        throw new ValidationException("Missing value for required field `materials`");
      }
      return new OnEncryptResponse(this);
    }
  }
}
