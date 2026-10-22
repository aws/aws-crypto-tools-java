// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keystore;

import software.amazon.cryptography.mpl.exceptions.ValidationException;

/** Output of {@link BranchKeyStore#createKey}. Immutable. */
public final class CreateKeyResponse {

  private final String branchKeyIdentifier;

  private CreateKeyResponse(Builder builder) {
    this.branchKeyIdentifier = builder.branchKeyIdentifier;
  }

  public static Builder builder() {
    return new Builder();
  }


  /** A builder holding this response's values. */
  public Builder toBuilder() {
    return new Builder().branchKeyIdentifier(branchKeyIdentifier);
  }

  /** The id of the created branch key. */
  public String branchKeyIdentifier() {
    return branchKeyIdentifier;
  }

  @Override
  public String toString() {
    return "CreateKeyResponse[" + branchKeyIdentifier + "]";
  }

  /** Not thread-safe. Requires {@code branchKeyIdentifier}. */
  public static final class Builder {

    private String branchKeyIdentifier;

    private Builder() {}

    public Builder branchKeyIdentifier(String branchKeyIdentifier) {
      this.branchKeyIdentifier = branchKeyIdentifier;
      return this;
    }

    public CreateKeyResponse build() {
      if (branchKeyIdentifier == null) {
        throw new ValidationException("Missing value for required field `branchKeyIdentifier`");
      }
      return new CreateKeyResponse(this);
    }
  }
}
