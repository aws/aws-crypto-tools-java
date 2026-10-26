// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.keystore;

import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

/** Output of {@link BranchKeyStore#createKeyStore}. Immutable. */
public final class CreateKeyStoreResponse {

  private final String tableArn;

  private CreateKeyStoreResponse(Builder builder) {
    this.tableArn = builder.tableArn;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this response's values. */
  public Builder toBuilder() {
    return new Builder().tableArn(tableArn);
  }

  /** The ARN of the DynamoDB table. */
  public String tableArn() {
    return tableArn;
  }

  @Override
  public String toString() {
    return "CreateKeyStoreResponse[" + tableArn + "]";
  }

  /** Not thread-safe. Requires {@code tableArn}. */
  public static final class Builder {

    private String tableArn;

    private Builder() {}

    public Builder tableArn(String tableArn) {
      this.tableArn = tableArn;
      return this;
    }

    public CreateKeyStoreResponse build() {
      if (tableArn == null) {
        throw new ValidationException("Missing value for required field `tableArn`");
      }
      return new CreateKeyStoreResponse(this);
    }
  }
}
