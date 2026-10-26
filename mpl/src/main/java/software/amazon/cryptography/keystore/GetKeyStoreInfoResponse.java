// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.keystore;

import java.util.List;
import java.util.Objects;

/** Output of {@link BranchKeyStore#getKeyStoreInfo}: the store's configuration. Immutable. */
public final class GetKeyStoreInfoResponse {

  private final String keyStoreId;
  private final String keyStoreName;
  private final String logicalKeyStoreName;
  private final List<String> grantTokens;
  private final KmsConfiguration kmsConfiguration;

  GetKeyStoreInfoResponse(
    String keyStoreId,
    String keyStoreName,
    String logicalKeyStoreName,
    List<String> grantTokens,
    KmsConfiguration kmsConfiguration
  ) {
    this.keyStoreId = keyStoreId;
    this.keyStoreName = keyStoreName;
    this.logicalKeyStoreName = logicalKeyStoreName;
    this.grantTokens = grantTokens;
    this.kmsConfiguration = kmsConfiguration;
  }

  public String keyStoreId() {
    return keyStoreId;
  }

  /** The DynamoDB table name. */
  public String keyStoreName() {
    return keyStoreName;
  }

  public String logicalKeyStoreName() {
    return logicalKeyStoreName;
  }

  /** Unmodifiable. */
  public List<String> grantTokens() {
    return grantTokens;
  }

  public KmsConfiguration kmsConfiguration() {
    return kmsConfiguration;
  }

  @Override
  public boolean equals(Object other) {
    if (!(other instanceof GetKeyStoreInfoResponse)) {
      return false;
    }
    GetKeyStoreInfoResponse that = (GetKeyStoreInfoResponse) other;
    return (
      keyStoreId.equals(that.keyStoreId) &&
      keyStoreName.equals(that.keyStoreName) &&
      logicalKeyStoreName.equals(that.logicalKeyStoreName) &&
      grantTokens.equals(that.grantTokens) &&
      kmsConfiguration.equals(that.kmsConfiguration)
    );
  }

  @Override
  public int hashCode() {
    return Objects.hash(keyStoreId, keyStoreName, logicalKeyStoreName, grantTokens, kmsConfiguration);
  }

  /** Grant tokens are not shown. */
  @Override
  public String toString() {
    return (
      "GetKeyStoreInfoResponse[" + keyStoreId + ", table " + keyStoreName + ", logical name " + logicalKeyStoreName + ", " +
      kmsConfiguration + ", " + grantTokens.size() + " grant tokens]"
    );
  }
}
