// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

/**
 * Output of {@link CryptographicMaterialsManager#decryptMaterials}. Immutable.
 * Holds the materials, not a copy; whoever receives the response owns them.
 */
public final class DecryptMaterialsResponse {

  private final DecryptionMaterials decryptionMaterials;

  private DecryptMaterialsResponse(Builder builder) {
    this.decryptionMaterials = builder.decryptionMaterials;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this response's values. */
  public Builder toBuilder() {
    return new Builder().decryptionMaterials(decryptionMaterials);
  }

  /** The materials for one message. */
  public DecryptionMaterials decryptionMaterials() {
    return decryptionMaterials;
  }

  @Override
  public String toString() {
    return "DecryptMaterialsResponse[" + decryptionMaterials + "]";
  }

  /** Not thread-safe. Requires decryption materials. */
  public static final class Builder {

    private DecryptionMaterials decryptionMaterials;

    private Builder() {}

    public Builder decryptionMaterials(DecryptionMaterials decryptionMaterials) {
      this.decryptionMaterials = decryptionMaterials;
      return this;
    }

    public DecryptMaterialsResponse build() {
      if (decryptionMaterials == null) {
        throw new ValidationException("Missing value for required field `decryptionMaterials`");
      }
      return new DecryptMaterialsResponse(this);
    }
  }
}
