// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

//= spec/framework/cmm-interface.md#encryption-materials-request
//= type=implication
//# The encryption materials request MUST include the following:
//#
//# - [Encryption Context](structures.md#encryption-context)
//#   - The encryption context provided MAY be empty.
//# - [Commitment Policy](./commitment-policy.md#supported-commitment-policy-enum)
//
//= spec/framework/cmm-interface.md#encryption-materials-request
//= type=implication
//# The encryption request MAY include the following:
//#
//# - [Algorithm Suite Id](algorithm-suites.md#algorithm-suite-id)
//# - Required Encryption Context Keys - a set of strings.
//# - Max Plaintext Length
//#   - This value represents the maximum length of the plaintext to be encrypted
//#     using the returned materials.
//#     The length of the plaintext to be encrypted MUST not be larger than this value.
/** Input to {@link CryptographicMaterialsManager#getEncryptionMaterials}. Immutable. */
public final class GetEncryptionMaterialsRequest {

  private final EncryptionContext encryptionContext;
  private final CommitmentPolicy commitmentPolicy;
  private final AlgorithmSuite algorithmSuiteId;
  private final Long maxPlaintextLength;
  private final List<String> requiredEncryptionContextKeys;

  private GetEncryptionMaterialsRequest(Builder builder) {
    this.encryptionContext = builder.encryptionContext;
    this.commitmentPolicy = builder.commitmentPolicy;
    this.algorithmSuiteId = builder.algorithmSuiteId;
    this.maxPlaintextLength = builder.maxPlaintextLength;
    this.requiredEncryptionContextKeys = Collections.unmodifiableList(new ArrayList<>(builder.requiredEncryptionContextKeys));
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this request's values. */
  public Builder toBuilder() {
    Builder builder = new Builder()
      .encryptionContext(encryptionContext)
      .commitmentPolicy(commitmentPolicy)
      .requiredEncryptionContextKeys(requiredEncryptionContextKeys);
    builder.algorithmSuiteId = algorithmSuiteId;
    builder.maxPlaintextLength = maxPlaintextLength;
    return builder;
  }

  public EncryptionContext encryptionContext() {
    return encryptionContext;
  }

  public CommitmentPolicy commitmentPolicy() {
    return commitmentPolicy;
  }

  /** The suite the caller requires; absent means the policy's default. */
  public Optional<AlgorithmSuite> algorithmSuiteId() {
    return Optional.ofNullable(algorithmSuiteId);
  }

  /**
   * An upper bound on the plaintext length; absent when the caller does not know it, for example when streaming.
   * Not checked, and no built-in manager or keyring reads it.
   */
  public OptionalLong maxPlaintextLength() {
    return maxPlaintextLength == null ? OptionalLong.empty() : OptionalLong.of(maxPlaintextLength);
  }

  public List<String> requiredEncryptionContextKeys() {
    return requiredEncryptionContextKeys;
  }

  @Override
  public String toString() {
    return (
      "GetEncryptionMaterialsRequest[" + commitmentPolicy + ", " + algorithmSuiteId + ", context keys " +
      encryptionContext.keySet() + ", required " + requiredEncryptionContextKeys + "]"
    );
  }

  /** Not thread-safe. Requires an encryption context and a commitment policy. */
  public static final class Builder {

    private EncryptionContext encryptionContext;
    private CommitmentPolicy commitmentPolicy;
    private AlgorithmSuite algorithmSuiteId;
    private Long maxPlaintextLength;
    private List<String> requiredEncryptionContextKeys = new ArrayList<>();

    private Builder() {}

    /** A plain map is copied into an {@link EncryptionContext}, which validates it; an {@code EncryptionContext} is used as is. */
    public Builder encryptionContext(Map<String, String> encryptionContext) {
      this.encryptionContext = encryptionContext == null ? null : EncryptionContext.copyOf(encryptionContext);
      return this;
    }

    public Builder commitmentPolicy(CommitmentPolicy commitmentPolicy) {
      this.commitmentPolicy = commitmentPolicy;
      return this;
    }

    public Builder algorithmSuiteId(AlgorithmSuite algorithmSuiteId) {
      this.algorithmSuiteId = algorithmSuiteId;
      return this;
    }

    /** Leave unset when the length is unknown. Any value is accepted. */
    public Builder maxPlaintextLength(long maxPlaintextLength) {
      this.maxPlaintextLength = maxPlaintextLength;
      return this;
    }

    public Builder requiredEncryptionContextKeys(Collection<String> keys) {
      this.requiredEncryptionContextKeys = new ArrayList<>(keys);
      return this;
    }

    /** The same as {@link #requiredEncryptionContextKeys(Collection)} with these values; a null array is passed on as a null collection. */
    public Builder requiredEncryptionContextKeys(String... keys) {
      return requiredEncryptionContextKeys(keys == null ? null : Arrays.asList(keys));
    }

    public GetEncryptionMaterialsRequest build() {
      if (encryptionContext == null) {
        throw new ValidationException("Missing value for required field `encryptionContext`");
      }
      if (commitmentPolicy == null) {
        throw new ValidationException("Missing value for required field `commitmentPolicy`");
      }
      return new GetEncryptionMaterialsRequest(this);
    }
  }
}
