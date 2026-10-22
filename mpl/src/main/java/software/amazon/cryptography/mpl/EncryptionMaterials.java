// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.security.auth.Destroyable;
import software.amazon.cryptography.mpl.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.MaterialsAccess;
import software.amazon.cryptography.mpl.internal.MaterialsRules;
import software.amazon.cryptography.mpl.internal.SecretBytesAccess;
import software.amazon.cryptography.mpl.internal.primitives.EcKeys;

//= spec/framework/structures.md#overview
//= type=implication
//# While these structures will usually be represented as objects, lower level languages MAY represent
//# these fields in a less strictly defined way as long as all field properties are still upheld.
//
//= spec/framework/structures.md#overview
//= type=exception
//= reason=The materials are Java objects, so the less strictly defined representation this permits is not used.
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

  static {
    MaterialsAccess.registerEncryption(EncryptionMaterials::new, materials -> materials.fields);
  }

  private final MaterialsRules.Encryption fields;

  private EncryptionMaterials(MaterialsRules.Encryption fields) {
    this.fields = fields;
  }

  /**
   * Starts materials for {@code suite}: no data key yet.
   * For a signing suite, {@link Builder#signingKeyPair} is required and the verification key is added
   * to the encryption context under {@code aws-crypto-public-key}.
   */
  public static Builder builder(AlgorithmSuite suite) {
    return new Builder(Objects.requireNonNull(suite, "suite"));
  }

  public AlgorithmSuite algorithmSuite() {
    return fields.suite;
  }

  public EncryptionContext encryptionContext() {
    return EncryptionContext.copyOf(fields.encryptionContext);
  }

  /** Context keys that must be supplied again on decrypt; they are not stored in the message. The order carries no meaning. */
  public List<String> requiredEncryptionContextKeys() {
    return Collections.unmodifiableList(fields.requiredEncryptionContextKeys);
  }

  public List<EncryptedDataKey> encryptedDataKeys() {
    return Collections.unmodifiableList(fields.encryptedDataKeys);
  }

  //= spec/framework/structures.md#plaintext-data-key
  //= type=implication
  //# The plaintext data key SHOULD be stored as immutable data.
  /** Owned by these materials; read it, do not destroy it. */
  public Optional<SecretBytes> plaintextDataKey() {
    return Optional.ofNullable(fields.plaintextDataKey);
  }

  //= spec/framework/structures.md#signing-key
  //= type=implication
  //# The value of this key MUST be kept secret.
  /**
   * The ECDSA private key of a signing suite: the private scalar as {@link java.math.BigInteger#toByteArray()} encodes it
   * (big-endian two's complement, so it may start with a zero byte). Owned by these materials.
   */
  public Optional<SecretBytes> signingKey() {
    return Optional.ofNullable(fields.signingKey);
  }

  /** {@link #signingKey()} as a JCA key on the suite's curve. */
  public Optional<PrivateKey> signingPrivateKey() {
    if (fields.signingKey == null) {
      return Optional.empty();
    }
    return Optional.of(SecretBytesAccess.apply(fields.signingKey, scalar -> EcKeys.privateKey(fields.suite.signature().get(), scalar)));
  }

  //= spec/framework/structures.md#symmetric-signing-keys
  //= type=implication
  //# The value of keys in this list MUST be kept secret.
  /** One HMAC key per encrypted data key, in the same order; empty unless the suite signs symmetrically. Owned by these materials. */
  public List<SecretBytes> symmetricSigningKeys() {
    return Collections.unmodifiableList(fields.symmetricSigningKeys);
  }

  /**
   * These materials with a plaintext data key.
   *
   * @throws InvalidMaterialsException if a key is already set or its length does not match the suite
   */
  public EncryptionMaterials withPlaintextDataKey(SecretBytes plaintextDataKey) {
    Objects.requireNonNull(plaintextDataKey, "plaintextDataKey");
    requireValid();
    if (fields.plaintextDataKey != null) {
      throw new InvalidMaterialsException("Attempt to modify plaintextDataKey.");
    }
    if (plaintextDataKey.length() != fields.suite.dataKeyLength()) {
      throw new InvalidMaterialsException("plaintextDataKey does not match Algorithm Suite specification.");
    }
    return copy(plaintextDataKey.copy(), fields.encryptedDataKeys, copies(fields.symmetricSigningKeys));
  }

  //= spec/framework/structures.md#encrypted-data-keys
  //= type=exception
  //= reason=Keyrings, including custom ones, produce the ciphertext; the materials cannot check that it holds this plaintext data key.
  //# The [ciphertext](#ciphertext) of each encrypted data key in this list MUST be an opaque form of the
  //# plaintext data key from this set of encryption materials.
  /** These materials with one more encrypted data key, for a suite without symmetric signing. */
  public EncryptionMaterials withEncryptedDataKey(EncryptedDataKey encryptedDataKey) {
    return addEncryptedDataKey(encryptedDataKey, null);
  }

  /** These materials with one more encrypted data key and its HMAC key, for a symmetric-signing (DBE) suite. */
  public EncryptionMaterials withEncryptedDataKey(EncryptedDataKey encryptedDataKey, SecretBytes symmetricSigningKey) {
    return addEncryptedDataKey(encryptedDataKey, Objects.requireNonNull(symmetricSigningKey, "symmetricSigningKey"));
  }

  /** Whether the materials can encrypt: a plaintext data key and at least one encrypted data key. */
  public boolean isReadyForEncrypt() {
    return MaterialsRules.isReadyForEncrypt(fields);
  }

  /** Whether these materials can follow {@code start}: nothing removed or changed, keys only added. */
  public boolean isValidTransitionFrom(EncryptionMaterials start) {
    return MaterialsRules.isValidTransition(start.fields, fields);
  }

  //= spec/framework/structures.md#plaintext-data-key
  //# The plaintext data key SHOULD offer an interface to zero the plaintext data key.
  /** Destroys the secrets these materials own; materials created from them by {@code with...} own separate copies. */
  @Override
  public void destroy() {
    destroy(fields.plaintextDataKey);
    destroy(fields.signingKey);
    fields.symmetricSigningKeys.forEach(EncryptionMaterials::destroy);
  }

  @Override
  public boolean isDestroyed() {
    return fields.plaintextDataKey != null && fields.plaintextDataKey.isDestroyed();
  }

  /** Suite, context keys, and provider ids; never secrets. */
  @Override
  public String toString() {
    List<String> providers = new ArrayList<>();
    for (EncryptedDataKey edk : fields.encryptedDataKeys) {
      providers.add(edk.keyProviderId());
    }
    return (
      "EncryptionMaterials[" + fields.suite + ", context keys " + fields.encryptionContext.keySet() +
      ", encrypted data keys " + providers + ", plaintext data key " + (fields.plaintextDataKey != null) + "]"
    );
  }

  private EncryptionMaterials addEncryptedDataKey(EncryptedDataKey encryptedDataKey, SecretBytes symmetricSigningKey) {
    Objects.requireNonNull(encryptedDataKey, "encryptedDataKey");
    requireValid();
    if (fields.plaintextDataKey == null) {
      throw new InvalidMaterialsException("Adding encrypted data keys without a plaintext data key is not allowed.");
    }
    if (symmetricSigningKey == null && fields.suite.isSymmetricSigning()) {
      throw new InvalidMaterialsException(
        "Adding encrypted data keys without a symmetric signing key when using symmetric signing is not allowed."
      );
    }
    if (symmetricSigningKey != null && !fields.suite.isSymmetricSigning()) {
      throw new InvalidMaterialsException(
        "Adding encrypted data keys with a symmetric signing key when not using symmetric signing is not allowed."
      );
    }
    List<EncryptedDataKey> edks = new ArrayList<>(fields.encryptedDataKeys);
    edks.add(encryptedDataKey);
    List<SecretBytes> symmetric = copies(fields.symmetricSigningKeys);
    if (symmetricSigningKey != null) {
      symmetric.add(symmetricSigningKey.copy());
    }
    return copy(fields.plaintextDataKey.copy(), edks, symmetric);
  }

  private void requireValid() {
    if (!MaterialsRules.isValid(fields)) {
      throw new InvalidMaterialsException("Attempt to modify invalid encryption material.");
    }
  }

  private EncryptionMaterials copy(SecretBytes plaintextDataKey, List<EncryptedDataKey> edks, List<SecretBytes> symmetric) {
    return new EncryptionMaterials(
      new MaterialsRules.Encryption(
        fields.suite,
        fields.encryptionContext,
        edks,
        fields.requiredEncryptionContextKeys,
        plaintextDataKey,
        fields.signingKey == null ? null : fields.signingKey.copy(),
        symmetric
      )
    );
  }

  private static List<SecretBytes> copies(List<SecretBytes> secrets) {
    List<SecretBytes> copies = new ArrayList<>(secrets.size());
    for (SecretBytes secret : secrets) {
      copies.add(secret.copy());
    }
    return copies;
  }

  private static void destroy(SecretBytes secret) {
    if (secret != null) {
      secret.destroy();
    }
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

    /** The same as {@link #requiredEncryptionContextKeys(Collection)}; a null array is a null collection. */
    public Builder requiredEncryptionContextKeys(String... keys) {
      return requiredEncryptionContextKeys(keys == null ? null : Arrays.asList(keys));
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
      return new EncryptionMaterials(
        new MaterialsRules.Encryption(
          suite,
          MaterialsRules.initialEncryptionContext(
            suite,
            encryptionContext,
            requiredEncryptionContextKeys,
            signingKey,
            verificationKey
          ),
          new ArrayList<>(),
          new ArrayList<>(requiredEncryptionContextKeys),
          null,
          signingKey,
          new ArrayList<>()
        )
      );
    }
  }
}
