// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keystore;

import java.util.function.Consumer;

/**
 * Where the hierarchical keyring and the AWS Database Encryption SDK get branch keys and beacon keys;
 * {@link DynamoDbKeyStore} is the provided implementation.
 * The keyring uses what an implementation returns without checking it, so it must return only key materials it decrypted with AWS KMS
 * under the same encryption context binding as {@code DynamoDbKeyStore}, and it must be thread-safe.
 * Exceptions it throws pass through unchanged; on decrypt the keyring collects them, one per encrypted data key,
 * in a {@link software.amazon.cryptography.materialproviders.exceptions.NoMatchingDataKeyException}.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/branch-key-store.md">branch key store</a>.
 */
public interface KeyStore {
  /** The ACTIVE version of a branch key. */
  GetActiveBranchKeyResponse getActiveBranchKey(GetActiveBranchKeyRequest request);

  /** {@link #getActiveBranchKey(GetActiveBranchKeyRequest)} with a request built by {@code request}. */
  default GetActiveBranchKeyResponse getActiveBranchKey(Consumer<GetActiveBranchKeyRequest.Builder> request) {
    GetActiveBranchKeyRequest.Builder builder = GetActiveBranchKeyRequest.builder();
    request.accept(builder);
    return getActiveBranchKey(builder.build());
  }

  /** One version of a branch key, ACTIVE or not. */
  GetBranchKeyVersionResponse getBranchKeyVersion(GetBranchKeyVersionRequest request);

  /** {@link #getBranchKeyVersion(GetBranchKeyVersionRequest)} with a request built by {@code request}. */
  default GetBranchKeyVersionResponse getBranchKeyVersion(Consumer<GetBranchKeyVersionRequest.Builder> request) {
    GetBranchKeyVersionRequest.Builder builder = GetBranchKeyVersionRequest.builder();
    request.accept(builder);
    return getBranchKeyVersion(builder.build());
  }

  /** The beacon key of a branch key. */
  GetBeaconKeyResponse getBeaconKey(GetBeaconKeyRequest request);

  /** {@link #getBeaconKey(GetBeaconKeyRequest)} with a request built by {@code request}. */
  default GetBeaconKeyResponse getBeaconKey(Consumer<GetBeaconKeyRequest.Builder> request) {
    GetBeaconKeyRequest.Builder builder = GetBeaconKeyRequest.builder();
    request.accept(builder);
    return getBeaconKey(builder.build());
  }

  /**
   * The store's configuration. The hierarchical keyring reads {@code logicalKeyStoreName} once, when it is built,
   * and keys its cache entries by it.
   */
  GetKeyStoreInfoResponse getKeyStoreInfo(GetKeyStoreInfoRequest request);

  /** The same as {@code getKeyStoreInfo(GetKeyStoreInfoRequest.builder().build())}. */
  default GetKeyStoreInfoResponse getKeyStoreInfo() {
    return getKeyStoreInfo(GetKeyStoreInfoRequest.builder().build());
  }

  /** {@link #getKeyStoreInfo(GetKeyStoreInfoRequest)} with a request built by {@code request}. */
  default GetKeyStoreInfoResponse getKeyStoreInfo(Consumer<GetKeyStoreInfoRequest.Builder> request) {
    GetKeyStoreInfoRequest.Builder builder = GetKeyStoreInfoRequest.builder();
    request.accept(builder);
    return getKeyStoreInfo(builder.build());
  }
}
