// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.keystore;

import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

/** Input to {@link DynamoDbKeyStore#getBranchKeyVersion}. Immutable. */
public final class GetBranchKeyVersionRequest {

  private final String branchKeyIdentifier;
  private final String branchKeyVersion;

  private GetBranchKeyVersionRequest(Builder builder) {
    this.branchKeyIdentifier = builder.branchKeyIdentifier;
    this.branchKeyVersion = builder.branchKeyVersion;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this request's values. */
  public Builder toBuilder() {
    return new Builder().branchKeyIdentifier(branchKeyIdentifier).branchKeyVersion(branchKeyVersion);
  }

  public String branchKeyIdentifier() {
    return branchKeyIdentifier;
  }

  public String branchKeyVersion() {
    return branchKeyVersion;
  }

  @Override
  public String toString() {
    return "GetBranchKeyVersionRequest[" + branchKeyIdentifier + ", " + branchKeyVersion + "]";
  }

  /** Not thread-safe. Requires {@code branchKeyIdentifier} and {@code branchKeyVersion}. */
  public static final class Builder {

    private String branchKeyIdentifier;
    private String branchKeyVersion;

    private Builder() {}

    public Builder branchKeyIdentifier(String branchKeyIdentifier) {
      this.branchKeyIdentifier = branchKeyIdentifier;
      return this;
    }

    public Builder branchKeyVersion(String branchKeyVersion) {
      this.branchKeyVersion = branchKeyVersion;
      return this;
    }

    public GetBranchKeyVersionRequest build() {
      if (branchKeyIdentifier == null) {
        throw new ValidationException("Missing value for required field `branchKeyIdentifier`");
      }
      if (branchKeyVersion == null) {
        throw new ValidationException("Missing value for required field `branchKeyVersion`");
      }
      return new GetBranchKeyVersionRequest(this);
    }
  }
}
