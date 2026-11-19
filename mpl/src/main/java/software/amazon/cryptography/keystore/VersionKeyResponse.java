// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.keystore;

/** Output of {@link DynamoDbKeyStore#versionKey}; it has no members yet. Immutable. */
public final class VersionKeyResponse {

  private VersionKeyResponse(Builder builder) {}

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this response's values. */
  public Builder toBuilder() {
    return new Builder();
  }

  @Override
  public String toString() {
    return "VersionKeyResponse[]";
  }

  /** Not thread-safe. */
  public static final class Builder {

    private Builder() {}

    public VersionKeyResponse build() {
      return new VersionKeyResponse(this);
    }
  }
}
