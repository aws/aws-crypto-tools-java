// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keystore;

import software.amazon.cryptography.mpl.exceptions.ValidationException;

/** Input to {@link BranchKeyStore#getBeaconKey}. Immutable. */
public final class GetBeaconKeyRequest {

  private final String branchKeyIdentifier;

  private GetBeaconKeyRequest(Builder builder) {
    this.branchKeyIdentifier = builder.branchKeyIdentifier;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** The same as {@code builder().branchKeyIdentifier(branchKeyIdentifier).build()}. */
  public static GetBeaconKeyRequest of(String branchKeyIdentifier) {
    return builder().branchKeyIdentifier(branchKeyIdentifier).build();
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
    return "GetBeaconKeyRequest[" + branchKeyIdentifier + "]";
  }

  /** Not thread-safe. Requires {@code branchKeyIdentifier}. */
  public static final class Builder {

    private String branchKeyIdentifier;

    private Builder() {}

    public Builder branchKeyIdentifier(String branchKeyIdentifier) {
      this.branchKeyIdentifier = branchKeyIdentifier;
      return this;
    }

    public GetBeaconKeyRequest build() {
      if (branchKeyIdentifier == null) {
        throw new ValidationException("Missing value for required field `branchKeyIdentifier`");
      }
      return new GetBeaconKeyRequest(this);
    }
  }
}
