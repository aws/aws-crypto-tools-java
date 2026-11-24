// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package software.amazon.cryptography.esdk;

import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.Keyring;

/**
 * Input to {@link EsdkClient#encryptingStream(EncryptStreamRequest, java.io.OutputStream)}: an
 * {@link EncryptRequest} without the plaintext, which is written to the stream. Immutable.
 */
public final class EncryptStreamRequest {

  private final Keyring keyring;
  private final CryptographicMaterialsManager materialsManager;
  private final EncryptionContext encryptionContext;
  private final EsdkAlgorithmSuite algorithmSuite;
  private final Integer frameLength;
  private final Long maxPlaintextLength;

  private EncryptStreamRequest(final Builder builder) {
    this.keyring = builder.keyring;
    this.materialsManager = builder.materialsManager;
    this.encryptionContext = builder.encryptionContext;
    this.algorithmSuite = builder.algorithmSuite;
    this.frameLength = builder.frameLength;
    this.maxPlaintextLength = builder.maxPlaintextLength;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this request's values. */
  public Builder toBuilder() {
    final Builder builder = new Builder();
    builder.keyring = keyring;
    builder.materialsManager = materialsManager;
    builder.encryptionContext = encryptionContext;
    builder.algorithmSuite = algorithmSuite;
    builder.frameLength = frameLength;
    builder.maxPlaintextLength = maxPlaintextLength;
    return builder;
  }

  public Optional<Keyring> keyring() {
    return Optional.ofNullable(keyring);
  }

  public Optional<CryptographicMaterialsManager> materialsManager() {
    return Optional.ofNullable(materialsManager);
  }

  public EncryptionContext encryptionContext() {
    return encryptionContext;
  }

  public Optional<EsdkAlgorithmSuite> algorithmSuite() {
    return Optional.ofNullable(algorithmSuite);
  }

  public OptionalInt frameLength() {
    return frameLength == null ? OptionalInt.empty() : OptionalInt.of(frameLength);
  }

  /**
   * An upper bound on the bytes written to the stream. The materials manager sees it, and a write
   * past it fails.
   */
  public OptionalLong maxPlaintextLength() {
    return maxPlaintextLength == null ? OptionalLong.empty() : OptionalLong.of(maxPlaintextLength);
  }

  /** Not thread-safe. The members are those of {@link EncryptRequest.Builder}. */
  public static final class Builder {

    private Keyring keyring;
    private CryptographicMaterialsManager materialsManager;
    private EncryptionContext encryptionContext = EncryptionContext.empty();
    private EsdkAlgorithmSuite algorithmSuite;
    private Integer frameLength;
    private Long maxPlaintextLength;

    private Builder() {}

    public Builder keyring(final Keyring keyring) {
      this.keyring = keyring;
      return this;
    }

    public Builder materialsManager(final CryptographicMaterialsManager materialsManager) {
      this.materialsManager = materialsManager;
      return this;
    }

    public Builder encryptionContext(final Map<String, String> encryptionContext) {
      this.encryptionContext = Requests.encryptionContext(encryptionContext);
      return this;
    }

    public Builder algorithmSuite(final EsdkAlgorithmSuite algorithmSuite) {
      this.algorithmSuite = algorithmSuite;
      return this;
    }

    public Builder frameLength(final int frameLength) {
      this.frameLength = frameLength;
      return this;
    }

    /** Not negative. */
    public Builder maxPlaintextLength(final long maxPlaintextLength) {
      this.maxPlaintextLength = maxPlaintextLength;
      return this;
    }

    /** @throws EsdkValidationException as {@link EncryptRequest.Builder#build()} does */
    public EncryptStreamRequest build() {
      Requests.requireOneMaterialSource(keyring, materialsManager);
      Requests.requirePositiveFrameLength(frameLength);
      if (maxPlaintextLength != null && maxPlaintextLength < 0) {
        throw new EsdkValidationException("maxPlaintextLength must not be negative");
      }
      return new EncryptStreamRequest(this);
    }
  }
}
