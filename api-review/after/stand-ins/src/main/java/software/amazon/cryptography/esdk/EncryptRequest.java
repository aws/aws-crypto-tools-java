// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package software.amazon.cryptography.esdk;

import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.Keyring;

/** Input to {@link EsdkClient#encrypt(EncryptRequest)}. Immutable. */
public final class EncryptRequest {

  private final byte[] plaintext;
  private final Keyring keyring;
  private final CryptographicMaterialsManager materialsManager;
  private final EncryptionContext encryptionContext;
  private final EsdkAlgorithmSuite algorithmSuite;
  private final Integer frameLength;

  private EncryptRequest(final Builder builder) {
    this.plaintext = builder.plaintext;
    this.keyring = builder.keyring;
    this.materialsManager = builder.materialsManager;
    this.encryptionContext = builder.encryptionContext;
    this.algorithmSuite = builder.algorithmSuite;
    this.frameLength = builder.frameLength;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this request's values. */
  public Builder toBuilder() {
    final Builder builder = new Builder();
    builder.plaintext = plaintext;
    builder.keyring = keyring;
    builder.materialsManager = materialsManager;
    builder.encryptionContext = encryptionContext;
    builder.algorithmSuite = algorithmSuite;
    builder.frameLength = frameLength;
    return builder;
  }

  /** The data to encrypt. A copy. */
  public byte[] plaintext() {
    return plaintext.clone();
  }

  /** The keyring that protects the data key; set exactly when no materials manager is. */
  public Optional<Keyring> keyring() {
    return Optional.ofNullable(keyring);
  }

  /** The materials manager that supplies the data key; set exactly when no keyring is. */
  public Optional<CryptographicMaterialsManager> materialsManager() {
    return Optional.ofNullable(materialsManager);
  }

  /** Bound to the message: authenticated, not encrypted. Empty if unset. */
  public EncryptionContext encryptionContext() {
    return encryptionContext;
  }

  /** The suite to encrypt with; if absent, the default for the client's commitment policy. */
  public Optional<EsdkAlgorithmSuite> algorithmSuite() {
    return Optional.ofNullable(algorithmSuite);
  }

  /** Bytes of plaintext per frame; if absent, 4096. */
  public OptionalInt frameLength() {
    return frameLength == null ? OptionalInt.empty() : OptionalInt.of(frameLength);
  }

  /** Not thread-safe. Requires {@code plaintext} and exactly one of the two material sources. */
  public static final class Builder {

    private byte[] plaintext;
    private Keyring keyring;
    private CryptographicMaterialsManager materialsManager;
    private EncryptionContext encryptionContext = EncryptionContext.empty();
    private EsdkAlgorithmSuite algorithmSuite;
    private Integer frameLength;

    private Builder() {}

    /** Copied. */
    public Builder plaintext(final byte[] plaintext) {
      this.plaintext = plaintext == null ? null : plaintext.clone();
      return this;
    }

    public Builder keyring(final Keyring keyring) {
      this.keyring = keyring;
      return this;
    }

    public Builder materialsManager(final CryptographicMaterialsManager materialsManager) {
      this.materialsManager = materialsManager;
      return this;
    }

    /** A plain map is copied into an {@link EncryptionContext}, which validates it. */
    public Builder encryptionContext(final Map<String, String> encryptionContext) {
      this.encryptionContext = Requests.encryptionContext(encryptionContext);
      return this;
    }

    /** An ESDK suite the client's commitment policy allows for encrypt. */
    public Builder algorithmSuite(final EsdkAlgorithmSuite algorithmSuite) {
      this.algorithmSuite = algorithmSuite;
      return this;
    }

    /** Positive. */
    public Builder frameLength(final int frameLength) {
      this.frameLength = frameLength;
      return this;
    }

    /**
     * @throws EsdkValidationException if a required member is missing, both material sources are set,
     *     the suite is not an ESDK suite, or the frame length is not positive
     */
    public EncryptRequest build() {
      if (plaintext == null) {
        throw new EsdkValidationException("Missing value for required field `plaintext`");
      }
      Requests.requireOneMaterialSource(keyring, materialsManager);
      Requests.requirePositiveFrameLength(frameLength);
      return new EncryptRequest(this);
    }
  }
}
