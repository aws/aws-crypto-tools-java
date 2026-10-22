// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.cache;

/** Output of {@link CryptographicMaterialsCache#deleteCacheEntry}; it has no members yet. Immutable. */
public final class DeleteCacheEntryResponse {

  private DeleteCacheEntryResponse(Builder builder) {}

  public static Builder builder() {
    return new Builder();
  }


  /** A builder holding this response's values. */
  public Builder toBuilder() {
    return new Builder();
  }

  @Override
  public String toString() {
    return "DeleteCacheEntryResponse[]";
  }

  /** Not thread-safe. */
  public static final class Builder {

    private Builder() {}

    public DeleteCacheEntryResponse build() {
      return new DeleteCacheEntryResponse(this);
    }
  }
}
