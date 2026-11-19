// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keystore;

import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

/** Output of {@link DynamoDbKeyStore#getBranchKeyVersion}. Immutable. */
public final class GetBranchKeyVersionResponse {

  private final BranchKeyMaterials branchKeyMaterials;

  private GetBranchKeyVersionResponse(Builder builder) {
    this.branchKeyMaterials = builder.branchKeyMaterials;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this response's values. */
  public Builder toBuilder() {
    return new Builder().branchKeyMaterials(branchKeyMaterials);
  }

  public BranchKeyMaterials branchKeyMaterials() {
    return branchKeyMaterials;
  }

  @Override
  public String toString() {
    return "GetBranchKeyVersionResponse[" + branchKeyMaterials + "]";
  }

  /** Not thread-safe. Requires {@code branchKeyMaterials}. */
  public static final class Builder {

    private BranchKeyMaterials branchKeyMaterials;

    private Builder() {}

    public Builder branchKeyMaterials(BranchKeyMaterials branchKeyMaterials) {
      this.branchKeyMaterials = branchKeyMaterials;
      return this;
    }

    public GetBranchKeyVersionResponse build() {
      if (branchKeyMaterials == null) {
        throw new ValidationException("Missing value for required field `branchKeyMaterials`");
      }
      return new GetBranchKeyVersionResponse(this);
    }
  }
}
