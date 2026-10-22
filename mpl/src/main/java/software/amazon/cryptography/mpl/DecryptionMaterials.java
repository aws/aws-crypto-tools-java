// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl;

import java.security.PublicKey;
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
import software.amazon.cryptography.mpl.internal.primitives.EcKeys;

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

  static {
    MaterialsAccess.registerDecryption(DecryptionMaterials::new, materials -> materials.fields);
  }

  private final MaterialsRules.Decryption fields;

  private DecryptionMaterials(MaterialsRules.Decryption fields) {
    this.fields = fields;
  }

  /**
   * Starts materials for {@code suite}: no data key yet. For a signing suite the verification key is
   * decoded from the context's {@code aws-crypto-public-key} entry, which must be present.
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

  public List<String> requiredEncryptionContextKeys() {
    return Collections.unmodifiableList(fields.requiredEncryptionContextKeys);
  }

  //= spec/framework/structures.md#plaintext-data-key-1
  //= type=implication
  //# The plaintext data key SHOULD be stored as immutable data.
  /** Owned by these materials; read it, do not destroy it. */
  public Optional<SecretBytes> plaintextDataKey() {
    return Optional.ofNullable(fields.plaintextDataKey);
  }

  /** The compressed public point from the encryption context; present only for a signing suite. A copy. */
  public Optional<byte[]> verificationKey() {
    return Optional.ofNullable(fields.verificationKey).map(byte[]::clone);
  }

  /**
   * {@link #verificationKey()} as a JCA key on the suite's curve.
   *
   * @throws ValidationException if the encoded key is not a point on the curve
   */
  public Optional<PublicKey> verificationPublicKey() {
    if (fields.verificationKey == null) {
      return Optional.empty();
    }
    return Optional.of(EcKeys.publicKey(fields.suite.signature().get(), fields.verificationKey));
  }

  //= spec/framework/structures.md#symmetric-signing-key
  //= type=implication
  //# This value MUST be kept secret.
  /** The HMAC key for the encrypted data key that was decrypted; present only for a symmetric-signing suite. Owned. */
  public Optional<SecretBytes> symmetricSigningKey() {
    return Optional.ofNullable(fields.symmetricSigningKey);
  }

  /**
   * @throws InvalidMaterialsException if a data key is already set, the length does not match the suite,
   *   or the suite needs a symmetric signing key
   */
  public DecryptionMaterials withPlaintextDataKey(SecretBytes plaintextDataKey) {
    return addDataKey(plaintextDataKey, null);
  }

  /** For a symmetric-signing (DBE) suite: the data key and its HMAC key together. */
  public DecryptionMaterials withPlaintextDataKey(SecretBytes plaintextDataKey, SecretBytes symmetricSigningKey) {
    return addDataKey(plaintextDataKey, Objects.requireNonNull(symmetricSigningKey, "symmetricSigningKey"));
  }

  public boolean isReadyForDecrypt() {
    return MaterialsRules.isReadyForDecrypt(fields);
  }

  public boolean isValidTransitionFrom(DecryptionMaterials start) {
    return MaterialsRules.isValidTransition(start.fields, fields);
  }

  //= spec/framework/structures.md#plaintext-data-key-1
  //# The plaintext data key SHOULD offer an interface to zero the plaintext data key.
  /** Destroys the secrets these materials own. */
  @Override
  public void destroy() {
    if (fields.plaintextDataKey != null) {
      fields.plaintextDataKey.destroy();
    }
    if (fields.symmetricSigningKey != null) {
      fields.symmetricSigningKey.destroy();
    }
  }

  @Override
  public boolean isDestroyed() {
    return fields.plaintextDataKey != null && fields.plaintextDataKey.isDestroyed();
  }

  /** Suite and context keys; never secrets. */
  @Override
  public String toString() {
    return (
      "DecryptionMaterials[" + fields.suite + ", context keys " + fields.encryptionContext.keySet() +
      ", plaintext data key " + (fields.plaintextDataKey != null) + "]"
    );
  }

  private DecryptionMaterials addDataKey(SecretBytes plaintextDataKey, SecretBytes symmetricSigningKey) {
    Objects.requireNonNull(plaintextDataKey, "plaintextDataKey");
    if (!MaterialsRules.isValid(fields)) {
      throw new InvalidMaterialsException("Attempt to modify invalid decryption material.");
    }
    if (fields.plaintextDataKey != null) {
      throw new InvalidMaterialsException("Attempt to modify plaintextDataKey.");
    }
    if (plaintextDataKey.length() != fields.suite.dataKeyLength()) {
      throw new InvalidMaterialsException("plaintextDataKey does not match Algorithm Suite specification.");
    }
    if ((symmetricSigningKey != null) != fields.suite.isSymmetricSigning()) {
      throw new InvalidMaterialsException(
        symmetricSigningKey == null
          ? "symmetric signature key must be added with plaintextDataKey if using an algorithm suite with symmetric signing."
          : "symmetric signature key cannot be added with plaintextDataKey if using an algorithm suite without symmetric signing."
      );
    }
    return new DecryptionMaterials(
      new MaterialsRules.Decryption(
        fields.suite,
        fields.encryptionContext,
        fields.requiredEncryptionContextKeys,
        plaintextDataKey.copy(),
        fields.verificationKey,
        symmetricSigningKey == null ? null : symmetricSigningKey.copy()
      )
    );
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

    /** The same as {@link #requiredEncryptionContextKeys(Collection)}; a null array is a null collection. */
    public Builder requiredEncryptionContextKeys(String... keys) {
      return requiredEncryptionContextKeys(keys == null ? null : Arrays.asList(keys));
    }

    /**
     * @throws ValidationException if a required key is missing, or the {@code aws-crypto-public-key} entry is
     *   missing (signing suite), present (other suites), or not base64
     */
    public DecryptionMaterials build() {
      byte[] verificationKey = MaterialsRules.initialVerificationKey(suite, encryptionContext, requiredEncryptionContextKeys);
      return new DecryptionMaterials(
        new MaterialsRules.Decryption(
          suite,
          encryptionContext,
          new ArrayList<>(requiredEncryptionContextKeys),
          null,
          verificationKey,
          null
        )
      );
    }
  }
}
