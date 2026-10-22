// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import software.amazon.cryptography.mpl.EncryptionContext;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

/** Input to {@link BranchKeyIdSupplier#getBranchKeyId}. Immutable. */
public final class GetBranchKeyIdRequest {

  private final EncryptionContext encryptionContext;

  private GetBranchKeyIdRequest(Builder builder) {
    this.encryptionContext = builder.encryptionContext;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this request's values. */
  public Builder toBuilder() {
    return new Builder().encryptionContext(encryptionContext);
  }

  /** The encryption context of the message. */
  public EncryptionContext encryptionContext() {
    return encryptionContext;
  }

  @Override
  public String toString() {
    return "GetBranchKeyIdRequest[" + encryptionContext + "]";
  }

  /** Not thread-safe. Requires {@code encryptionContext}. */
  public static final class Builder {

    private EncryptionContext encryptionContext;

    private Builder() {}

    public Builder encryptionContext(EncryptionContext encryptionContext) {
      this.encryptionContext = encryptionContext;
      return this;
    }

    public GetBranchKeyIdRequest build() {
      if (encryptionContext == null) {
        throw new ValidationException("Missing value for required field `encryptionContext`");
      }
      return new GetBranchKeyIdRequest(this);
    }
  }
}
