// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package software.amazon.cryptography.esdk;

import java.util.Map;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.EncryptionContext;

/** Output of {@link EsdkClient#decrypt(DecryptRequest)}. Immutable. */
public final class DecryptResponse {

  private final byte[] plaintext;
  private final EncryptionContext encryptionContext;
  private final EsdkAlgorithmSuite algorithmSuite;

  private DecryptResponse(final Builder builder) {
    this.plaintext = builder.plaintext;
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
    builder.plaintext = plaintext;
    builder.encryptionContext = encryptionContext;
    builder.algorithmSuite = algorithmSuite;
    return builder;
  }

  /** The decrypted data. A copy. */
  public byte[] plaintext() {
    return plaintext.clone();
  }

  /** The encryption context bound to the message. */
  public EncryptionContext encryptionContext() {
    return encryptionContext;
  }

  /** The suite the message is encrypted with. */
  public EsdkAlgorithmSuite algorithmSuite() {
    return algorithmSuite;
  }

  /** Not thread-safe. Requires every member. */
  public static final class Builder {

    private byte[] plaintext;
    private EncryptionContext encryptionContext;
    private EsdkAlgorithmSuite algorithmSuite;

    private Builder() {}

    /** Copied. */
    public Builder plaintext(final byte[] plaintext) {
      this.plaintext = plaintext == null ? null : plaintext.clone();
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
    public DecryptResponse build() {
      if (plaintext == null) {
        throw new EsdkValidationException("Missing value for required field `plaintext`");
      }
      if (encryptionContext == null) {
        throw new EsdkValidationException("Missing value for required field `encryptionContext`");
      }
      if (algorithmSuite == null) {
        throw new EsdkValidationException("Missing value for required field `algorithmSuite`");
      }
      return new DecryptResponse(this);
    }
  }
}
