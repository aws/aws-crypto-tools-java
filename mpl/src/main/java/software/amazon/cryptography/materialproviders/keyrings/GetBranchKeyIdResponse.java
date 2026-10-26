// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keyrings;

import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

/** Output of {@link BranchKeyIdSupplier#getBranchKeyId}. Immutable. */
public final class GetBranchKeyIdResponse {

  private final String branchKeyId;

  private GetBranchKeyIdResponse(Builder builder) {
    this.branchKeyId = builder.branchKeyId;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this response's values. */
  public Builder toBuilder() {
    return new Builder().branchKeyId(branchKeyId);
  }

  /** The branch key for the message. */
  public String branchKeyId() {
    return branchKeyId;
  }

  @Override
  public String toString() {
    return "GetBranchKeyIdResponse[" + branchKeyId + "]";
  }

  /** Not thread-safe. Requires {@code branchKeyId}. */
  public static final class Builder {

    private String branchKeyId;

    private Builder() {}

    public Builder branchKeyId(String branchKeyId) {
      this.branchKeyId = branchKeyId;
      return this;
    }

    public GetBranchKeyIdResponse build() {
      if (branchKeyId == null) {
        throw new ValidationException("Missing value for required field `branchKeyId`");
      }
      return new GetBranchKeyIdResponse(this);
    }
  }
}
