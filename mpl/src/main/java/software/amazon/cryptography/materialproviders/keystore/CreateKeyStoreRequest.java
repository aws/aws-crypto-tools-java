// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keystore;

/** Input to {@link DynamoDbKeyStore#createKeyStore}; it has no members yet. Immutable. */
public final class CreateKeyStoreRequest {

  private CreateKeyStoreRequest(Builder builder) {}

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this request's values. */
  public Builder toBuilder() {
    return new Builder();
  }

  @Override
  public String toString() {
    return "CreateKeyStoreRequest[]";
  }

  /** Not thread-safe. */
  public static final class Builder {

    private Builder() {}

    public CreateKeyStoreRequest build() {
      return new CreateKeyStoreRequest(this);
    }
  }
}
