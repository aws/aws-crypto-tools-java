// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keystore;

import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

/** Output of {@link DynamoDbKeyStore#createKey}. Immutable. */
public final class CreateKeyResponse {

  private final String branchKeyId;

  private CreateKeyResponse(Builder builder) {
    this.branchKeyId = builder.branchKeyId;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this response's values. */
  public Builder toBuilder() {
    return new Builder().branchKeyId(branchKeyId);
  }

  /** The id of the created branch key. */
  public String branchKeyId() {
    return branchKeyId;
  }

  @Override
  public String toString() {
    return "CreateKeyResponse[" + branchKeyId + "]";
  }

  /** Not thread-safe. Requires {@code branchKeyId}. */
  public static final class Builder {

    private String branchKeyId;

    private Builder() {}

    public Builder branchKeyId(String branchKeyId) {
      this.branchKeyId = branchKeyId;
      return this;
    }

    public CreateKeyResponse build() {
      if (branchKeyId == null) {
        throw new ValidationException("Missing value for required field `branchKeyId`");
      }
      return new CreateKeyResponse(this);
    }
  }
}
