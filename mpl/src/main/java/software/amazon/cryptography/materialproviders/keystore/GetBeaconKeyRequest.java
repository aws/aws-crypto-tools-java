// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keystore;

import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

/** Input to {@link KeyStore#getBeaconKey}. Immutable. */
public final class GetBeaconKeyRequest {

  private final String branchKeyId;

  private GetBeaconKeyRequest(Builder builder) {
    this.branchKeyId = builder.branchKeyId;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this request's values. */
  public Builder toBuilder() {
    return new Builder().branchKeyId(branchKeyId);
  }

  public String branchKeyId() {
    return branchKeyId;
  }

  @Override
  public String toString() {
    return "GetBeaconKeyRequest[" + branchKeyId + "]";
  }

  /** Not thread-safe. Requires {@code branchKeyId}. */
  public static final class Builder {

    private String branchKeyId;

    private Builder() {}

    public Builder branchKeyId(String branchKeyId) {
      this.branchKeyId = branchKeyId;
      return this;
    }

    public GetBeaconKeyRequest build() {
      if (branchKeyId == null) {
        throw new ValidationException("Missing value for required field `branchKeyId`");
      }
      return new GetBeaconKeyRequest(this);
    }
  }
}
