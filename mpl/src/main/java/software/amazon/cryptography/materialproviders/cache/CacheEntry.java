// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.cache;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.keystore.BeaconKeyMaterials;
import software.amazon.cryptography.materialproviders.keystore.BranchKeyMaterials;

/**
 * Cached materials with their lifetime: a branch key (hierarchical keyring)
 * or a beacon key (AWS Database Encryption SDK searchable encryption). Immutable.
 */
//= spec/framework/cryptographic-materials-cache.md#cache-entry
//= type=exception
//= reason=A cache entry holds materials, creation time, and expiry time but no usage metadata; the branch key and beacon key caches never read it.
//# A cache entry represents an entry in the cryptographic materials cache
//# and MUST have the following information.
//#
//# - [Materials](#materials)
//# - [Creation Time](#creation-time)
//# - [Expiry Time](#expiry-time)
//# - [Usage Metadata](#usage-metadata)
//
//= spec/framework/cryptographic-materials-cache.md#usage-metadata
//= type=exception
//= reason=Cache entries carry no usage metadata, so there is nothing to update.
//# Updating usage metadata SHOULD be atomic.
public final class CacheEntry {

  private final BranchKeyMaterials branchKeyMaterials;
  private final BeaconKeyMaterials beaconKeyMaterials;
  private final Instant creationTime;
  private final Instant expiryTime;

  private CacheEntry(Builder builder) {
    this.branchKeyMaterials = builder.branchKeyMaterials;
    this.beaconKeyMaterials = builder.beaconKeyMaterials;
    this.creationTime = builder.creationTime;
    this.expiryTime = builder.expiryTime;
  }

  public static Builder builder() {
    return new Builder();
  }

  public Builder toBuilder() {
    return new Builder()
      .branchKeyMaterials(branchKeyMaterials)
      .beaconKeyMaterials(beaconKeyMaterials)
      .creationTime(creationTime)
      .expiryTime(expiryTime);
  }

  /** Present exactly when {@link #beaconKeyMaterials()} is absent. */
  public Optional<BranchKeyMaterials> branchKeyMaterials() {
    return Optional.ofNullable(branchKeyMaterials);
  }

  public Optional<BeaconKeyMaterials> beaconKeyMaterials() {
    return Optional.ofNullable(beaconKeyMaterials);
  }

  public Instant creationTime() {
    return creationTime;
  }

  /**
   * The built-in caches count time in whole seconds:
   * they return the entry until the end of the second that contains this instant.
   */
  //= spec/framework/cryptographic-materials-cache.md#time-to-live-ttl
  //= type=implication
  //# Each cache entry has a time-to-live (TTL)
  //# that represents a point in time at which the cache entry
  //# MUST be considered invalid.
  public Instant expiryTime() {
    return expiryTime;
  }

  @Override
  public boolean equals(Object other) {
    if (!(other instanceof CacheEntry)) {
      return false;
    }
    CacheEntry that = (CacheEntry) other;
    return (
      Objects.equals(branchKeyMaterials, that.branchKeyMaterials) &&
      Objects.equals(beaconKeyMaterials, that.beaconKeyMaterials) &&
      creationTime.equals(that.creationTime) &&
      expiryTime.equals(that.expiryTime)
    );
  }

  @Override
  public int hashCode() {
    return Objects.hash(branchKeyMaterials, beaconKeyMaterials, creationTime, expiryTime);
  }

  /** Times and the kind of materials; never secrets. */
  @Override
  public String toString() {
    return (
      "CacheEntry[" + (branchKeyMaterials != null ? "branch key" : "beacon key") +
      ", created " + creationTime + ", expires " + expiryTime + "]"
    );
  }

  /** Exactly one of branchKeyMaterials and beaconKeyMaterials, plus both times, is required. */
  public static final class Builder {

    private BranchKeyMaterials branchKeyMaterials;
    private BeaconKeyMaterials beaconKeyMaterials;
    private Instant creationTime;
    private Instant expiryTime;

    private Builder() {}

    public Builder branchKeyMaterials(BranchKeyMaterials branchKeyMaterials) {
      this.branchKeyMaterials = branchKeyMaterials;
      return this;
    }

    public Builder beaconKeyMaterials(BeaconKeyMaterials beaconKeyMaterials) {
      this.beaconKeyMaterials = beaconKeyMaterials;
      return this;
    }

    public Builder creationTime(Instant creationTime) {
      this.creationTime = creationTime;
      return this;
    }

    public Builder expiryTime(Instant expiryTime) {
      this.expiryTime = expiryTime;
      return this;
    }

    public CacheEntry build() {
      if ((branchKeyMaterials == null) == (beaconKeyMaterials == null)) {
        throw new ValidationException("A cache entry holds exactly one of branchKeyMaterials and beaconKeyMaterials");
      }
      if (creationTime == null) {
        throw new ValidationException("Missing value for required field `creationTime`");
      }
      if (expiryTime == null) {
        throw new ValidationException("Missing value for required field `expiryTime`");
      }
      return new CacheEntry(this);
    }
  }
}
