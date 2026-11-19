// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keystore;

import java.util.Map;
import java.util.Optional;
import software.amazon.cryptography.materialproviders.EncryptionContext;

/** Input to {@link DynamoDbKeyStore#createKey}. Immutable. */
public final class CreateKeyRequest {

  private final String branchKeyId;
  private final EncryptionContext encryptionContext;

  private CreateKeyRequest(Builder builder) {
    this.branchKeyId = builder.branchKeyId;
    this.encryptionContext = builder.encryptionContext;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this request's values. */
  public Builder toBuilder() {
    Builder builder = new Builder();
    builder.branchKeyId = branchKeyId;
    builder.encryptionContext = encryptionContext;
    return builder;
  }

  /** Absent means a random version 4 UUID. */
  public Optional<String> branchKeyId() {
    return Optional.ofNullable(branchKeyId);
  }

  /** Bound into the branch key's KMS encryption context. */
  public Optional<EncryptionContext> encryptionContext() {
    return Optional.ofNullable(encryptionContext);
  }

  @Override
  public String toString() {
    return "CreateKeyRequest[" + branchKeyId + ", " + encryptionContext + "]";
  }

  /** Not thread-safe. */
  public static final class Builder {

    private String branchKeyId;
    private EncryptionContext encryptionContext;

    private Builder() {}

    /** Must not be empty. Requires a non-empty {@code encryptionContext}. */
    public Builder branchKeyId(String branchKeyId) {
      this.branchKeyId = branchKeyId;
      return this;
    }

    /** A plain map is copied into an {@link EncryptionContext}, which validates it; an {@code EncryptionContext} is used as is. */
    public Builder encryptionContext(Map<String, String> encryptionContext) {
      this.encryptionContext = encryptionContext == null ? null : EncryptionContext.copyOf(encryptionContext);
      return this;
    }

    public CreateKeyRequest build() {
      return new CreateKeyRequest(this);
    }
  }
}
