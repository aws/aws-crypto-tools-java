// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.security.auth.Destroyable;
import software.amazon.cryptography.mpl.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

//= spec/framework/structures.md#overview
//= type=implication
//# While these structures will usually be represented as objects, lower level languages MAY represent
//# these fields in a less strictly defined way as long as all field properties are still upheld.
//
//= spec/framework/structures.md#structure-2
//= type=implication
//# This structure MUST include the following fields:
//#
//# - [Algorithm Suite](#algorithm-suite)
//# - [Encrypted Data Keys](#encrypted-data-keys)
//# - [Encryption Context](#encryption-context-1)
//# - [Required Encryption Context Keys](#required-encryption-context-keys)
//
//= spec/framework/structures.md#structure-2
//= type=implication
//# This structure MAY include any of the following fields:
//#
//# - [Plaintext Data Key](#plaintext-data-key)
//# - [Signing Key](#signing-key)
/**
 * What an encrypting caller needs: the algorithm suite, encryption context, plaintext data key,
 * and the encrypted copies of that key that go in the message.
 *
 * <p>Immutable. Keyrings return a new instance with {@code with...} methods, and the library checks every
 * keyring result against its input (the plaintext data key added or unchanged, encrypted data keys only added).
 * Each instance owns its secrets; {@code toString} shows the suite, context keys, and provider ids only.
 */
public final class EncryptionMaterials implements Destroyable {

  private EncryptionMaterials() {}

  /**
   * Starts materials for {@code suite}: no data key yet.
   * For a signing suite, {@link Builder#signingKeyPair} is required and the verification key is added
   * to the encryption context under {@code aws-crypto-public-key}.
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

  /** Context keys that must be supplied again on decrypt; they are not stored in the message. The order carries no meaning. */
  public List<String> requiredEncryptionContextKeys() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  public List<EncryptedDataKey> encryptedDataKeys() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  //= spec/framework/structures.md#plaintext-data-key
  //= type=implication
  //# The plaintext data key SHOULD be stored as immutable data.
  /** Owned by these materials; read it, do not destroy it. */
  public Optional<SecretBytes> plaintextDataKey() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  //= spec/framework/structures.md#signing-key
  //= type=implication
  //# The value of this key MUST be kept secret.
  /**
   * The ECDSA private key of a signing suite: the private scalar as {@link java.math.BigInteger#toByteArray()} encodes it
   * (big-endian two's complement, so it may start with a zero byte). Owned by these materials.
   */
  public Optional<SecretBytes> signingKey() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** {@link #signingKey()} as a JCA key on the suite's curve. */
  public Optional<PrivateKey> signingPrivateKey() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  //= spec/framework/structures.md#symmetric-signing-keys
  //= type=implication
  //# The value of keys in this list MUST be kept secret.
  /** One HMAC key per encrypted data key, in the same order; empty unless the suite signs symmetrically. Owned by these materials. */
  public List<SecretBytes> symmetricSigningKeys() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /**
   * These materials with a plaintext data key.
   *
   * @throws InvalidMaterialsException if a key is already set or its length does not match the suite
   */
  public EncryptionMaterials withPlaintextDataKey(SecretBytes plaintextDataKey) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** These materials with one more encrypted data key, for a suite without symmetric signing. */
  public EncryptionMaterials withEncryptedDataKey(EncryptedDataKey encryptedDataKey) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** These materials with one more encrypted data key and its HMAC key, for a symmetric-signing (DBE) suite. */
  public EncryptionMaterials withEncryptedDataKey(EncryptedDataKey encryptedDataKey, SecretBytes symmetricSigningKey) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** Whether the materials can encrypt: a plaintext data key and at least one encrypted data key. */
  public boolean isReadyForEncrypt() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** Whether these materials can follow {@code start}: nothing removed or changed, keys only added. */
  public boolean isValidTransitionFrom(EncryptionMaterials start) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** Destroys the secrets these materials own; materials created from them by {@code with...} own separate copies. */
  @Override
  public void destroy() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  @Override
  public boolean isDestroyed() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** Suite, context keys, and provider ids; never secrets. */
  @Override
  public String toString() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** Not thread-safe. {@link #build()} validates as InitializeEncryptionMaterials did. */
  public static final class Builder {

    private final AlgorithmSuite suite;
    private EncryptionContext encryptionContext = EncryptionContext.empty();
    private List<String> requiredEncryptionContextKeys = new ArrayList<>();
    private SecretBytes signingKey;
    private byte[] verificationKey;

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
     * An ECDSA key pair on the suite's curve: the private scalar as {@link java.math.BigInteger#toByteArray()} encodes it,
     * and the compressed public point. Both copied.
     */
    public Builder signingKeyPair(SecretBytes signingKey, byte[] verificationKey) {
      this.signingKey = signingKey.copy();
      this.verificationKey = verificationKey.clone();
      return this;
    }

    /**
     * @throws ValidationException if the context uses the reserved key or lacks a required key,
     *   or a signing key pair is missing for a signing suite or present for another
     */
    public EncryptionMaterials build() {
      throw new UnsupportedOperationException("not implemented yet");
    }
  }
}
