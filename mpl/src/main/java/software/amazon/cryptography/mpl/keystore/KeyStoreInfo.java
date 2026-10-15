// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keystore;

import java.util.List;
import java.util.Objects;

/** Configuration of a branch key store, as reported by {@link BranchKeyStore#getKeyStoreInfo()}. Immutable. */
public final class KeyStoreInfo {

  private final String keyStoreId;
  private final String keyStoreName;
  private final String logicalKeyStoreName;
  private final List<String> grantTokens;
  private final KmsConfiguration kmsConfiguration;

  KeyStoreInfo(
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
    if (!(other instanceof KeyStoreInfo)) {
      return false;
    }
    KeyStoreInfo that = (KeyStoreInfo) other;
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
      "KeyStoreInfo[" + keyStoreId + ", table " + keyStoreName + ", logical name " + logicalKeyStoreName + ", " +
      kmsConfiguration + ", " + grantTokens.size() + " grant tokens]"
    );
  }
}
