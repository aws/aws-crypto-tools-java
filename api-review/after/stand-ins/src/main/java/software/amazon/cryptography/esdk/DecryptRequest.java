// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package software.amazon.cryptography.esdk;

import java.util.Map;
import java.util.Optional;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.Keyring;

/** Input to {@link EsdkClient#decrypt(DecryptRequest)}. Immutable. */
public final class DecryptRequest {

  private final byte[] ciphertext;
  private final Keyring keyring;
  private final CryptographicMaterialsManager materialsManager;
  private final EncryptionContext encryptionContext;

  private DecryptRequest(final Builder builder) {
    this.ciphertext = builder.ciphertext;
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
    builder.ciphertext = ciphertext;
    builder.keyring = keyring;
    builder.materialsManager = materialsManager;
    builder.encryptionContext = encryptionContext;
    return builder;
  }

  /** The encrypted message. A copy. */
  public byte[] ciphertext() {
    return ciphertext.clone();
  }

  public Optional<Keyring> keyring() {
    return Optional.ofNullable(keyring);
  }

  public Optional<CryptographicMaterialsManager> materialsManager() {
    return Optional.ofNullable(materialsManager);
  }

  /**
   * Pairs the message's encryption context must contain; decrypt fails if one is missing or has
   * another value. Empty if unset.
   */
  public EncryptionContext encryptionContext() {
    return encryptionContext;
  }

  /** Not thread-safe. Requires {@code ciphertext} and exactly one of the two material sources. */
  public static final class Builder {

    private byte[] ciphertext;
    private Keyring keyring;
    private CryptographicMaterialsManager materialsManager;
    private EncryptionContext encryptionContext = EncryptionContext.empty();

    private Builder() {}

    /** Copied. */
    public Builder ciphertext(final byte[] ciphertext) {
      this.ciphertext = ciphertext == null ? null : ciphertext.clone();
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

    /** @throws EsdkValidationException if a required member is missing or both sources are set */
    public DecryptRequest build() {
      if (ciphertext == null) {
        throw new EsdkValidationException("Missing value for required field `ciphertext`");
      }
      Requests.requireOneMaterialSource(keyring, materialsManager);
      return new DecryptRequest(this);
    }
  }
}
