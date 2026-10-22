// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl;

import software.amazon.cryptography.mpl.exceptions.ValidationException;

/**
 * Output of {@link Keyring#onDecrypt}. Immutable.
 * Holds the materials, not a copy; whoever receives the response owns them.
 */
public final class OnDecryptResponse {

  private final DecryptionMaterials materials;

  private OnDecryptResponse(Builder builder) {
    this.materials = builder.materials;
  }

  public static Builder builder() {
    return new Builder();
  }


  /** A builder holding this response's values. */
  public Builder toBuilder() {
    return new Builder().materials(materials);
  }

  /** The request's materials with the plaintext data key added. */
  public DecryptionMaterials materials() {
    return materials;
  }

  @Override
  public String toString() {
    return "OnDecryptResponse[" + materials + "]";
  }

  /** Not thread-safe. Requires materials. */
  public static final class Builder {

    private DecryptionMaterials materials;

    private Builder() {}

    public Builder materials(DecryptionMaterials materials) {
      this.materials = materials;
      return this;
    }

    public OnDecryptResponse build() {
      if (materials == null) {
        throw new ValidationException("Missing value for required field `materials`");
      }
      return new OnDecryptResponse(this);
    }
  }
}
