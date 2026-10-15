// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import java.util.Optional;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnEncryptRequest;
import software.amazon.cryptography.mpl.cache.CacheType;
import software.amazon.cryptography.mpl.keystore.BranchKeyStore;

/**
 * Wraps data keys with branch keys from a branch key store, caching branch keys so most operations make no KMS call.
 * Thread-safe when its cache is: not with {@link CacheType#singleThreaded}, nor with a shared cache that is not thread-safe.
 *
 * <p>Each encrypted data key has provider id {@code aws-kms-hierarchy}, provider info = the branch key id as UTF-8,
 * and ciphertext = {@code salt (16) || IV (12) || branch key version as a 16-byte UUID || AES-GCM ciphertext || tag (16)}.
 * The AES key is derived from the branch key and the salt (NIST SP 800-108 counter mode, HMAC-SHA-256);
 * the AAD is {@code "aws-kms-hierarchy" || branch key id || version bytes || canonical encryption context}.
 *
 * <p>A cached branch key is used while it is at most {@code ttlSeconds} old, even when another keyring sharing the cache
 * cached it with a longer TTL.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/aws-kms/aws-kms-hierarchical-keyring.md">AWS KMS hierarchical keyring</a>.
 */
//= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#interface
//= type=implication
//# MUST implement the [AWS Encryption SDK Keyring interface](../keyring-interface.md#interface)
public final class AwsKmsHierarchicalKeyring implements Keyring {

  //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
  //= type=implication
  //# MUST use an authentication tag byte of length 16.

  private final String branchKeyId;
  private final BranchKeyIdSupplier branchKeyIdSupplier;
  private final BranchKeyStore keyStore;
  private final long ttlSeconds;
  private final CacheType cacheType;
  private final String partitionId;

  private AwsKmsHierarchicalKeyring() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  public static Builder builder() {
    return new Builder();
  }

  /** The branch key for every message. Exactly one of this and {@code branchKeyIdSupplier}. */
  public Optional<String> branchKeyId() {
    return Optional.ofNullable(branchKeyId);
  }

  /** Chooses the branch key per message from its encryption context. */
  public Optional<BranchKeyIdSupplier> branchKeyIdSupplier() {
    return Optional.ofNullable(branchKeyIdSupplier);
  }

  /** Where branch keys come from. */
  public BranchKeyStore keyStore() {
    return keyStore;
  }

  /** How long a cached branch key is used, in seconds; greater than zero. See {@link CacheType} for the check against the cache. */
  public long ttlSeconds() {
    return ttlSeconds;
  }

  /** Where branch keys are cached; default {@code CacheType.defaultCache(1000)}. */
  public Optional<CacheType> cache() {
    return Optional.ofNullable(cacheType);
  }

  /** Keyrings sharing a cache share entries only when their partition ids and key stores' logical names are equal; default: a random id, so nothing is shared. */
  public Optional<String> partitionId() {
    return Optional.ofNullable(partitionId);
  }

  @Override
  //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
  //= type=implication
  //# OnEncrypt MUST take [encryption materials]
  //# (../structures.md#encryption-materials) as input.
  public EncryptionMaterials onEncrypt(OnEncryptRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  @Override
  public DecryptionMaterials onDecrypt(OnDecryptRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /**
   * Not thread-safe.
   * Requires {@code keyStore}, {@code ttlSeconds}.
   * {@link #build()} throws {@link software.amazon.cryptography.mpl.exceptions.ValidationException} for invalid settings.
   */
  public static final class Builder {

    private String branchKeyId;
    private BranchKeyIdSupplier branchKeyIdSupplier;
    private BranchKeyStore keyStore;
    private long ttlSeconds;
    private boolean ttlSecondsSet;
    private CacheType cache;
    private String partitionId;

    private Builder() {}

    /** The branch key for every message. Exactly one of this and {@code branchKeyIdSupplier}. */
    public Builder branchKeyId(String branchKeyId) {
      this.branchKeyId = branchKeyId;
      return this;
    }

    /** Chooses the branch key per message from its encryption context. */
    public Builder branchKeyIdSupplier(BranchKeyIdSupplier branchKeyIdSupplier) {
      this.branchKeyIdSupplier = branchKeyIdSupplier;
      return this;
    }

    /** Where branch keys come from. */
    public Builder keyStore(BranchKeyStore keyStore) {
      this.keyStore = keyStore;
      return this;
    }

    /** How long a cached branch key is used, in seconds; greater than zero. See {@link CacheType} for the check against the cache. */
    public Builder ttlSeconds(long ttlSeconds) {
      this.ttlSeconds = ttlSeconds;
      this.ttlSecondsSet = true;
      return this;
    }

    /**
     * Where branch keys are cached; default {@code CacheType.defaultCache(1000)}.
     * Without this setting {@link #build()} requires {@code ttlSeconds} above the default 10-second grace period;
     * with {@code CacheType.defaultCache} given explicitly it does not (see {@link CacheType}).
     */
    public Builder cache(CacheType cache) {
      this.cache = cache;
      return this;
    }

    /** Keyrings sharing a cache share entries only when their partition ids and key stores' logical names are equal; default: a random id, so nothing is shared. */
    public Builder partitionId(String partitionId) {
      this.partitionId = partitionId;
      return this;
    }

    public AwsKmsHierarchicalKeyring build() {
      throw new UnsupportedOperationException("not implemented yet");
    }
  }
}
