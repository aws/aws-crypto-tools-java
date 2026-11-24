// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package software.amazon.cryptography.esdk;

import java.util.Map;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.EncryptionContext;

/** Output of {@link EsdkClient#encrypt(EncryptRequest)}. Immutable. */
public final class EncryptResponse {

  private final byte[] ciphertext;
  private final EncryptionContext encryptionContext;
  private final EsdkAlgorithmSuite algorithmSuite;

  private EncryptResponse(final Builder builder) {
    this.ciphertext = builder.ciphertext;
    this.encryptionContext = builder.encryptionContext;
    this.algorithmSuite = builder.algorithmSuite;
  }

  /** For callers that build responses, such as a test double of {@link EsdkClient}. */
  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this response's values. */
  public Builder toBuilder() {
    final Builder builder = new Builder();
    builder.ciphertext = ciphertext;
    builder.encryptionContext = encryptionContext;
    builder.algorithmSuite = algorithmSuite;
    return builder;
  }

  /** The encrypted message. A copy. */
  public byte[] ciphertext() {
    return ciphertext.clone();
  }

  /**
   * The encryption context bound to the message, including any pairs the materials manager added.
   */
  public EncryptionContext encryptionContext() {
    return encryptionContext;
  }

  /** The suite the message is encrypted with. */
  public EsdkAlgorithmSuite algorithmSuite() {
    return algorithmSuite;
  }

  /** Not thread-safe. Requires every member. */
  public static final class Builder {

    private byte[] ciphertext;
    private EncryptionContext encryptionContext;
    private EsdkAlgorithmSuite algorithmSuite;

    private Builder() {}

    /** Copied. */
    public Builder ciphertext(final byte[] ciphertext) {
      this.ciphertext = ciphertext == null ? null : ciphertext.clone();
      return this;
    }

    /** A plain map is copied into an {@link EncryptionContext}, which validates it. */
    public Builder encryptionContext(final Map<String, String> encryptionContext) {
      this.encryptionContext =
          encryptionContext == null ? null : Requests.encryptionContext(encryptionContext);
      return this;
    }

    public Builder algorithmSuite(final EsdkAlgorithmSuite algorithmSuite) {
      this.algorithmSuite = algorithmSuite;
      return this;
    }

    /** @throws EsdkValidationException if a member is missing */
    public EncryptResponse build() {
      if (ciphertext == null) {
        throw new EsdkValidationException("Missing value for required field `ciphertext`");
      }
      if (encryptionContext == null) {
        throw new EsdkValidationException("Missing value for required field `encryptionContext`");
      }
      if (algorithmSuite == null) {
        throw new EsdkValidationException("Missing value for required field `algorithmSuite`");
      }
      return new EncryptResponse(this);
    }
  }
}
