// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl;

import software.amazon.cryptography.mpl.exceptions.ValidationException;

/**
 * Output of {@link CryptographicMaterialsManager#getEncryptionMaterials}. Immutable.
 * Holds the materials, not a copy; whoever receives the response owns them.
 */
public final class GetEncryptionMaterialsResponse {

  private final EncryptionMaterials encryptionMaterials;

  private GetEncryptionMaterialsResponse(Builder builder) {
    this.encryptionMaterials = builder.encryptionMaterials;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this response's values. */
  public Builder toBuilder() {
    return new Builder().encryptionMaterials(encryptionMaterials);
  }

  /** The materials for one message. */
  public EncryptionMaterials encryptionMaterials() {
    return encryptionMaterials;
  }

  @Override
  public String toString() {
    return "GetEncryptionMaterialsResponse[" + encryptionMaterials + "]";
  }

  /** Not thread-safe. Requires encryption materials. */
  public static final class Builder {

    private EncryptionMaterials encryptionMaterials;

    private Builder() {}

    public Builder encryptionMaterials(EncryptionMaterials encryptionMaterials) {
      this.encryptionMaterials = encryptionMaterials;
      return this;
    }

    public GetEncryptionMaterialsResponse build() {
      if (encryptionMaterials == null) {
        throw new ValidationException("Missing value for required field `encryptionMaterials`");
      }
      return new GetEncryptionMaterialsResponse(this);
    }
  }
}
