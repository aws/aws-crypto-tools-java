// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keystore;

import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

/** Input to {@link DynamoDbKeyStore#getBranchKeyVersion}. Immutable. */
public final class GetBranchKeyVersionRequest {

  private final String branchKeyId;
  private final String branchKeyVersion;

  private GetBranchKeyVersionRequest(Builder builder) {
    this.branchKeyId = builder.branchKeyId;
    this.branchKeyVersion = builder.branchKeyVersion;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this request's values. */
  public Builder toBuilder() {
    return new Builder().branchKeyId(branchKeyId).branchKeyVersion(branchKeyVersion);
  }

  public String branchKeyId() {
    return branchKeyId;
  }

  public String branchKeyVersion() {
    return branchKeyVersion;
  }

  @Override
  public String toString() {
    return "GetBranchKeyVersionRequest[" + branchKeyId + ", " + branchKeyVersion + "]";
  }

  /** Not thread-safe. Requires {@code branchKeyId} and {@code branchKeyVersion}. */
  public static final class Builder {

    private String branchKeyId;
    private String branchKeyVersion;

    private Builder() {}

    public Builder branchKeyId(String branchKeyId) {
      this.branchKeyId = branchKeyId;
      return this;
    }

    public Builder branchKeyVersion(String branchKeyVersion) {
      this.branchKeyVersion = branchKeyVersion;
      return this;
    }

    public GetBranchKeyVersionRequest build() {
      if (branchKeyId == null) {
        throw new ValidationException("Missing value for required field `branchKeyId`");
      }
      if (branchKeyVersion == null) {
        throw new ValidationException("Missing value for required field `branchKeyVersion`");
      }
      return new GetBranchKeyVersionRequest(this);
    }
  }
}
