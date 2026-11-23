// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keystore;

import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

/** Output of {@link KeyStore#getBeaconKey}. Immutable. */
public final class GetBeaconKeyResponse {

  private final BeaconKeyMaterials beaconKeyMaterials;

  private GetBeaconKeyResponse(Builder builder) {
    this.beaconKeyMaterials = builder.beaconKeyMaterials;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this response's values. */
  public Builder toBuilder() {
    return new Builder().beaconKeyMaterials(beaconKeyMaterials);
  }

  public BeaconKeyMaterials beaconKeyMaterials() {
    return beaconKeyMaterials;
  }

  @Override
  public String toString() {
    return "GetBeaconKeyResponse[" + beaconKeyMaterials + "]";
  }

  /** Not thread-safe. Requires {@code beaconKeyMaterials}. */
  public static final class Builder {

    private BeaconKeyMaterials beaconKeyMaterials;

    private Builder() {}

    public Builder beaconKeyMaterials(BeaconKeyMaterials beaconKeyMaterials) {
      this.beaconKeyMaterials = beaconKeyMaterials;
      return this;
    }

    public GetBeaconKeyResponse build() {
      if (beaconKeyMaterials == null) {
        throw new ValidationException("Missing value for required field `beaconKeyMaterials`");
      }
      return new GetBeaconKeyResponse(this);
    }
  }
}
