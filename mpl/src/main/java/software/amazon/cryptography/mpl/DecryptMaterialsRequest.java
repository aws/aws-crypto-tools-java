// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

//= spec/framework/cmm-interface.md#decrypt-materials-request
//= type=implication
//# The decrypt materials request MUST include the following:
//#
//# - [Algorithm Suite Id](algorithm-suites.md#algorithm-suite-id)
//# - [Commitment Policy](./commitment-policy.md#supported-commitment-policy-enum)
//# - [Encrypted Data Keys](structures.md#encrypted-data-keys)
//# - [Encryption Context](structures.md#encryption-context)
//#   - The encryption context provided MAY be empty.
//
//= spec/framework/cmm-interface.md#decrypt-materials-request
//= type=implication
//# The decrypt materials request MAY include the following:
//#
//# - [Reproduced Encryption Context](structures.md#encryption-context)
/** Input to {@link CryptographicMaterialsManager#decryptMaterials}. Immutable. */
public final class DecryptMaterialsRequest {

  private final AlgorithmSuite algorithmSuiteId;
  private final CommitmentPolicy commitmentPolicy;
  private final List<EncryptedDataKey> encryptedDataKeys;
  private final EncryptionContext encryptionContext;
  private final EncryptionContext reproducedEncryptionContext;

  private DecryptMaterialsRequest(Builder builder) {
    this.algorithmSuiteId = builder.algorithmSuiteId;
    this.commitmentPolicy = builder.commitmentPolicy;
    this.encryptedDataKeys = Collections.unmodifiableList(new ArrayList<>(builder.encryptedDataKeys));
    this.encryptionContext = builder.encryptionContext;
    this.reproducedEncryptionContext = builder.reproducedEncryptionContext;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this request's values. */
  public Builder toBuilder() {
    return new Builder()
      .algorithmSuiteId(algorithmSuiteId)
      .commitmentPolicy(commitmentPolicy)
      .encryptedDataKeys(encryptedDataKeys)
      .encryptionContext(encryptionContext)
      .reproducedEncryptionContext(reproducedEncryptionContext);
  }

  public AlgorithmSuite algorithmSuiteId() {
    return algorithmSuiteId;
  }

  public CommitmentPolicy commitmentPolicy() {
    return commitmentPolicy;
  }

  public List<EncryptedDataKey> encryptedDataKeys() {
    return encryptedDataKeys;
  }

  /** The context stored in the message. */
  public EncryptionContext encryptionContext() {
    return encryptionContext;
  }

  /**
   * Context the caller supplies again on decrypt; it must agree with the stored context where keys overlap.
   * An empty context counts as absent.
   */
  public Optional<EncryptionContext> reproducedEncryptionContext() {
    return reproducedEncryptionContext == null || reproducedEncryptionContext.isEmpty()
      ? Optional.empty()
      : Optional.of(reproducedEncryptionContext);
  }

  @Override
  public String toString() {
    return (
      "DecryptMaterialsRequest[" + algorithmSuiteId + ", " + commitmentPolicy + ", " + encryptedDataKeys.size() +
      " encrypted data keys, context keys " + encryptionContext.keySet() + "]"
    );
  }

  /** Not thread-safe. Requires a suite, a policy, encrypted data keys, and the stored encryption context. */
  public static final class Builder {

    private AlgorithmSuite algorithmSuiteId;
    private CommitmentPolicy commitmentPolicy;
    private List<EncryptedDataKey> encryptedDataKeys;
    private EncryptionContext encryptionContext;
    private EncryptionContext reproducedEncryptionContext;

    private Builder() {}

    public Builder algorithmSuiteId(AlgorithmSuite algorithmSuiteId) {
      this.algorithmSuiteId = algorithmSuiteId;
      return this;
    }

    public Builder commitmentPolicy(CommitmentPolicy commitmentPolicy) {
      this.commitmentPolicy = commitmentPolicy;
      return this;
    }

    public Builder encryptedDataKeys(Collection<EncryptedDataKey> encryptedDataKeys) {
      this.encryptedDataKeys = new ArrayList<>(encryptedDataKeys);
      return this;
    }

    /** A plain map is copied into an {@link EncryptionContext}, which validates it; an {@code EncryptionContext} is used as is. */
    public Builder encryptionContext(Map<String, String> encryptionContext) {
      this.encryptionContext = encryptionContext == null ? null : EncryptionContext.copyOf(encryptionContext);
      return this;
    }

    /** A plain map is copied into an {@link EncryptionContext}, which validates it; an {@code EncryptionContext} is used as is. */
    public Builder reproducedEncryptionContext(Map<String, String> reproducedEncryptionContext) {
      this.reproducedEncryptionContext = reproducedEncryptionContext == null ? null : EncryptionContext.copyOf(reproducedEncryptionContext);
      return this;
    }

    public DecryptMaterialsRequest build() {
      if (algorithmSuiteId == null) {
        throw new ValidationException("Missing value for required field `algorithmSuiteId`");
      }
      if (commitmentPolicy == null) {
        throw new ValidationException("Missing value for required field `commitmentPolicy`");
      }
      if (encryptedDataKeys == null) {
        throw new ValidationException("Missing value for required field `encryptedDataKeys`");
      }
      if (encryptionContext == null) {
        throw new ValidationException("Missing value for required field `encryptionContext`");
      }
      return new DecryptMaterialsRequest(this);
    }
  }
}
