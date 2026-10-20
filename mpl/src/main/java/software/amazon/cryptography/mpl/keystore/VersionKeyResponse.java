// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keystore;

/** Output of {@link BranchKeyStore#versionKey}; it has no members yet. Immutable. */
public final class VersionKeyResponse {

  private VersionKeyResponse(Builder builder) {}

  public static Builder builder() {
    return new Builder();
  }

  /** The same as {@code builder().build()}. */
  public static VersionKeyResponse of() {
    return builder().build();
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
