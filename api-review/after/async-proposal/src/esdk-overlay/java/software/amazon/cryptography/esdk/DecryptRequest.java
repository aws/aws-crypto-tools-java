// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package software.amazon.cryptography.esdk;

import java.util.Map;
import java.util.Optional;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.Keyring;
import spike.AsyncKeyring;

/** Input to {@link EsdkClient#decrypt(DecryptRequest)}. Immutable. */
public final class DecryptRequest {

  private final byte[] ciphertext;
  private final Keyring keyring;
  private final AsyncKeyring asyncKeyring;
  private final CryptographicMaterialsManager materialsManager;
  private final EncryptionContext encryptionContext;

  private DecryptRequest(final Builder builder) {
    this.ciphertext = builder.ciphertext;
    this.keyring = builder.keyring;
    this.asyncKeyring = builder.asyncKeyring;
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
    builder.asyncKeyring = asyncKeyring;
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
    private AsyncKeyring asyncKeyring;
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

    /** Proposal: an async keyring, accepted only by EsdkAsyncClient. */
    public Builder keyring(final AsyncKeyring asyncKeyring) {
      this.asyncKeyring = asyncKeyring;
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
      if (keyring != null && asyncKeyring != null) {
        throw new EsdkValidationException("Set one keyring, sync or async");
      }
      if (asyncKeyring == null) {
        Requests.requireOneMaterialSource(keyring, materialsManager);
      } else if (materialsManager != null) {
        throw new EsdkValidationException("Exactly one of `keyring` or `materialsManager` is required");
      }
      return new DecryptRequest(this);
    }
  }
}
