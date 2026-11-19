// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keystore;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

/** Output of {@link DynamoDbKeyStore#getKeyStoreInfo}: the store's configuration. Immutable. */
public final class GetKeyStoreInfoResponse {

  private final String keyStoreId;
  private final String keyStoreName;
  private final String logicalKeyStoreName;
  private final List<String> grantTokens;
  private final KmsConfiguration kmsConfiguration;

  private GetKeyStoreInfoResponse(Builder builder) {
    this.keyStoreId = builder.keyStoreId;
    this.keyStoreName = builder.keyStoreName;
    this.logicalKeyStoreName = builder.logicalKeyStoreName;
    this.grantTokens = Collections.unmodifiableList(new ArrayList<>(builder.grantTokens));
    this.kmsConfiguration = builder.kmsConfiguration;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this response's values. */
  public Builder toBuilder() {
    return new Builder()
      .keyStoreId(keyStoreId)
      .keyStoreName(keyStoreName)
      .logicalKeyStoreName(logicalKeyStoreName)
      .grantTokens(grantTokens)
      .kmsConfiguration(kmsConfiguration);
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

  /** Not thread-safe. Requires every member except {@code grantTokens}, which defaults to none. */
  public static final class Builder {

    private String keyStoreId;
    private String keyStoreName;
    private String logicalKeyStoreName;
    private List<String> grantTokens = Collections.emptyList();
    private KmsConfiguration kmsConfiguration;

    private Builder() {}

    public Builder keyStoreId(String keyStoreId) {
      this.keyStoreId = keyStoreId;
      return this;
    }

    /** The DynamoDB table name. */
    public Builder keyStoreName(String keyStoreName) {
      this.keyStoreName = keyStoreName;
      return this;
    }

    public Builder logicalKeyStoreName(String logicalKeyStoreName) {
      this.logicalKeyStoreName = logicalKeyStoreName;
      return this;
    }

    public Builder grantTokens(Collection<String> grantTokens) {
      List<String> copy = new ArrayList<>(grantTokens);
      for (String token : copy) {
        Objects.requireNonNull(token, "grant token");
      }
      this.grantTokens = copy;
      return this;
    }

    /** The same as {@link #grantTokens(Collection)} with these values; a null array is passed on as a null collection. */
    public Builder grantTokens(String... grantTokens) {
      return grantTokens(grantTokens == null ? null : Arrays.asList(grantTokens));
    }

    public Builder kmsConfiguration(KmsConfiguration kmsConfiguration) {
      this.kmsConfiguration = kmsConfiguration;
      return this;
    }

    public GetKeyStoreInfoResponse build() {
      if (keyStoreId == null) {
        throw new ValidationException("Missing value for required field `keyStoreId`");
      }
      if (keyStoreName == null) {
        throw new ValidationException("Missing value for required field `keyStoreName`");
      }
      if (logicalKeyStoreName == null) {
        throw new ValidationException("Missing value for required field `logicalKeyStoreName`");
      }
      if (kmsConfiguration == null) {
        throw new ValidationException("Missing value for required field `kmsConfiguration`");
      }
      return new GetKeyStoreInfoResponse(this);
    }
  }
}
