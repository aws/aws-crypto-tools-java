// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.security.auth.Destroyable;
import software.amazon.cryptography.mpl.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

//= spec/framework/structures.md#fields
//= type=implication
//# This structure MUST include the following fields:
//#
//# - [Algorithm Suite](#algorithm-suite-1)
//# - [Encryption Context](#encryption-context-2)
//# - [Required Encryption Context Keys](#required-encryption-context-keys-1)
//
//= spec/framework/structures.md#fields
//= type=implication
//# This structure MAY include any of the following fields:
//#
//# - [Plaintext Data Key](#plaintext-data-key-1)
//# - [Verification Key](#verification-key)
/**
 * What a decrypting caller needs: the algorithm suite, encryption context, and the plaintext data key
 * a keyring recovered.
 *
 * <p>Immutable. A keyring returns {@link #withPlaintextDataKey}; a keyring given materials that already hold
 * a data key must fail, so the first keyring to succeed wins.
 */
public final class DecryptionMaterials implements Destroyable {

  private DecryptionMaterials() {}

  /**
   * Starts materials for {@code suite}: no data key yet. For a signing suite the verification key is
   * decoded from the context's {@code aws-crypto-public-key} entry, which must be present.
   */
  public static Builder builder(AlgorithmSuite suite) {
    return new Builder(Objects.requireNonNull(suite, "suite"));
  }

  public AlgorithmSuite algorithmSuite() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  public EncryptionContext encryptionContext() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  public List<String> requiredEncryptionContextKeys() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  //= spec/framework/structures.md#plaintext-data-key-1
  //= type=implication
  //# The plaintext data key SHOULD be stored as immutable data.
  /** Owned by these materials; read it, do not destroy it. */
  public Optional<SecretBytes> plaintextDataKey() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** The compressed public point from the encryption context; present only for a signing suite. A copy. */
  public Optional<byte[]> verificationKey() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /**
   * {@link #verificationKey()} as a JCA key on the suite's curve.
   *
   * @throws ValidationException if the encoded key is not a point on the curve
   */
  public Optional<PublicKey> verificationPublicKey() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  //= spec/framework/structures.md#symmetric-signing-key
  //= type=implication
  //# This value MUST be kept secret.
  /** The HMAC key for the encrypted data key that was decrypted; present only for a symmetric-signing suite. Owned. */
  public Optional<SecretBytes> symmetricSigningKey() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /**
   * @throws InvalidMaterialsException if a data key is already set, the length does not match the suite,
   *   or the suite needs a symmetric signing key
   */
  public DecryptionMaterials withPlaintextDataKey(SecretBytes plaintextDataKey) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** For a symmetric-signing (DBE) suite: the data key and its HMAC key together. */
  public DecryptionMaterials withPlaintextDataKey(SecretBytes plaintextDataKey, SecretBytes symmetricSigningKey) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  public boolean isReadyForDecrypt() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  public boolean isValidTransitionFrom(DecryptionMaterials start) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** Destroys the secrets these materials own. */
  @Override
  public void destroy() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  @Override
  public boolean isDestroyed() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** Suite and context keys; never secrets. */
  @Override
  public String toString() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** Not thread-safe. {@link #build()} validates as InitializeDecryptionMaterials did. */
  public static final class Builder {

    private final AlgorithmSuite suite;
    private EncryptionContext encryptionContext = EncryptionContext.empty();
    private List<String> requiredEncryptionContextKeys = new ArrayList<>();

    private Builder(AlgorithmSuite suite) {
      this.suite = suite;
    }

    /** A plain map is copied into an {@link EncryptionContext}, which validates it; an {@code EncryptionContext} is used as is. */
    public Builder encryptionContext(Map<String, String> encryptionContext) {
      this.encryptionContext = EncryptionContext.copyOf(Objects.requireNonNull(encryptionContext, "encryptionContext"));
      return this;
    }

    public Builder requiredEncryptionContextKeys(Collection<String> keys) {
      this.requiredEncryptionContextKeys = new ArrayList<>(keys);
      return this;
    }

    /**
     * @throws ValidationException if a required key is missing, or the {@code aws-crypto-public-key} entry is
     *   missing (signing suite), present (other suites), or not base64
     */
    public DecryptionMaterials build() {
      throw new UnsupportedOperationException("not implemented yet");
    }
  }
}
