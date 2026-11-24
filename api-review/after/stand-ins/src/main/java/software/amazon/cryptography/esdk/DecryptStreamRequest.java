// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package software.amazon.cryptography.esdk;

import java.util.Map;
import java.util.Optional;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.Keyring;

/**
 * Input to {@link EsdkClient#decryptingStream(DecryptStreamRequest, java.io.InputStream)}: a {@link
 * DecryptRequest} without the ciphertext, which is read from the stream. Immutable.
 */
public final class DecryptStreamRequest {

  private final Keyring keyring;
  private final CryptographicMaterialsManager materialsManager;
  private final EncryptionContext encryptionContext;

  private DecryptStreamRequest(final Builder builder) {
    this.keyring = builder.keyring;
    this.materialsManager = builder.materialsManager;
    this.encryptionContext = builder.encryptionContext;
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

  /** Not thread-safe. The members are those of {@link DecryptRequest.Builder}. */
  public static final class Builder {

    private Keyring keyring;
    private CryptographicMaterialsManager materialsManager;
    private EncryptionContext encryptionContext = EncryptionContext.empty();

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

    /** @throws EsdkValidationException if not exactly one of the two material sources is set */
    public DecryptStreamRequest build() {
      Requests.requireOneMaterialSource(keyring, materialsManager);
      return new DecryptStreamRequest(this);
    }
  }
}
