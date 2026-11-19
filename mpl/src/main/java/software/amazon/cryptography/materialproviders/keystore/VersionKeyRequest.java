// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keystore;

import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

/** Input to {@link DynamoDbKeyStore#versionKey}. Immutable. */
public final class VersionKeyRequest {

  private final String branchKeyIdentifier;

  private VersionKeyRequest(Builder builder) {
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
    return "VersionKeyRequest[" + branchKeyIdentifier + "]";
  }

  /** Not thread-safe. Requires {@code branchKeyIdentifier}. */
  public static final class Builder {

    private String branchKeyIdentifier;

    private Builder() {}

    public Builder branchKeyIdentifier(String branchKeyIdentifier) {
      this.branchKeyIdentifier = branchKeyIdentifier;
      return this;
    }

    public VersionKeyRequest build() {
      if (branchKeyIdentifier == null) {
        throw new ValidationException("Missing value for required field `branchKeyIdentifier`");
      }
      return new VersionKeyRequest(this);
    }
  }
}
