// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.keystore;

import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

/** Input to {@link BranchKeyStore#getActiveBranchKey}. Immutable. */
public final class GetActiveBranchKeyRequest {

  private final String branchKeyIdentifier;

  private GetActiveBranchKeyRequest(Builder builder) {
    this.branchKeyIdentifier = builder.branchKeyIdentifier;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this request's values. */
  public Builder toBuilder() {
    return new Builder().branchKeyIdentifier(branchKeyIdentifier);
  }

  public String branchKeyIdentifier() {
    return branchKeyIdentifier;
  }

  @Override
  public String toString() {
    return "GetActiveBranchKeyRequest[" + branchKeyIdentifier + "]";
  }

  /** Not thread-safe. Requires {@code branchKeyIdentifier}. */
  public static final class Builder {

    private String branchKeyIdentifier;

    private Builder() {}

    public Builder branchKeyIdentifier(String branchKeyIdentifier) {
      this.branchKeyIdentifier = branchKeyIdentifier;
      return this;
    }

    public GetActiveBranchKeyRequest build() {
      if (branchKeyIdentifier == null) {
        throw new ValidationException("Missing value for required field `branchKeyIdentifier`");
      }
      return new GetActiveBranchKeyRequest(this);
    }
  }
}
