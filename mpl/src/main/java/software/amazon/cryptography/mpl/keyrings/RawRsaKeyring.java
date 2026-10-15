// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnEncryptRequest;
import software.amazon.cryptography.mpl.SecretBytes;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

/**
 * Wraps data keys with a local RSA key pair.
 *
 * <p>Each encrypted data key has provider id = key namespace, provider info = key name (UTF-8),
 * and ciphertext = the RSA encryption of the data key (or, for DBE suites, of the intermediate key).
 * An empty key is treated as no key. Thread-safe.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/raw-rsa-keyring.md">Raw RSA keyring</a>.
 */
public final class RawRsaKeyring implements Keyring {

  private final String keyNamespace;
  private final String keyName;
  private final byte[] keyNameBytes;
  //= spec/framework/raw-rsa-keyring.md#padding-scheme
  //= type=implication
  //# This value MUST correspond with one of the [supported padding schemes]
  //# (#supported-padding-schemes).
  private final PaddingScheme paddingScheme;
  private final byte[] publicKey;
  private final SecretBytes privateKey;

  private RawRsaKeyring(Builder builder, byte[] keyNameBytes) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Recorded in each encrypted data key. Not {@code aws-kms}. */
  public String keyNamespace() {
    return keyNamespace;
  }

  /** Recorded in each encrypted data key. */
  public String keyName() {
    return keyName;
  }

  /** The RSA encryption padding. */
  public PaddingScheme paddingScheme() {
    return paddingScheme;
  }

  /** UTF-8 PEM (SubjectPublicKeyInfo); required to encrypt. Parsed when first used, as the reference does. A copy. */
  public Optional<byte[]> publicKey() {
    return Optional.ofNullable(publicKey).map(byte[]::clone);
  }

  @Override
  //= spec/framework/raw-rsa-keyring.md#onencrypt
  //= type=implication
  //# OnEncrypt MUST take [encryption materials](structures.md#encryption-
  //# materials) as input.
  public EncryptionMaterials onEncrypt(OnEncryptRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  @Override
  //= spec/framework/raw-rsa-keyring.md#ondecrypt
  //= type=implication
  //# OnDecrypt MUST take [decryption materials](structures.md#decryption-
  //# materials) and a list of [encrypted data keys]
  //# (structures.md#encrypted-data-key) as input.
  public DecryptionMaterials onDecrypt(OnDecryptRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /**
   * Not thread-safe. At least one of {@code publicKey} and {@code privateKey} is required.
   * Requires {@code keyNamespace}, {@code keyName}, {@code paddingScheme}.
   * {@link #build()} throws {@link ValidationException} for invalid settings.
   */
  //= spec/framework/raw-rsa-keyring.md#initialization
  //= type=implication
  //# On keyring initialization, the caller MUST provide the following:
  //# - [Key Namespace](./keyring-interface.md#key-namespace)
  //# - [Key Name](./keyring-interface.md#key-name)
  //# - [Padding Scheme](#padding-scheme)
  //# - [Public Key](#public-key) and/or [Private Key](#private-key)
  public static final class Builder {

    private String keyNamespace;
    private String keyName;
    private PaddingScheme paddingScheme;
    private byte[] publicKey;
    private SecretBytes privateKey;

    private Builder() {}

    /** Recorded in each encrypted data key. Not {@code aws-kms}. */
    public Builder keyNamespace(String keyNamespace) {
      this.keyNamespace = keyNamespace;
      return this;
    }

    /** Recorded in each encrypted data key. */
    public Builder keyName(String keyName) {
      this.keyName = keyName;
      return this;
    }

    /** The RSA encryption padding. */
    public Builder paddingScheme(PaddingScheme paddingScheme) {
      this.paddingScheme = paddingScheme;
      return this;
    }

    /** UTF-8 PEM (SubjectPublicKeyInfo); required to encrypt. Parsed when first used, as the reference does. Copied. */
    public Builder publicKey(byte[] publicKey) {
      this.publicKey = publicKey == null ? null : publicKey.clone();
      return this;
    }

    /** UTF-8 PEM (PKCS #8); required to decrypt. Parsed when first used, as the reference does. Copied. */
    public Builder privateKey(SecretBytes privateKey) {
      this.privateKey = privateKey == null ? null : privateKey.copy();
      return this;
    }

    /**
     * {@link #publicKey(byte[])} with the PEM of {@code publicKey.getEncoded()}, so the keyring behaves as with those bytes.
     *
     * @throws ValidationException if the key has no encoding
     */
    public Builder publicKey(PublicKey publicKey) {
      throw new UnsupportedOperationException("not implemented yet");
    }

    /**
     * {@link #privateKey(SecretBytes)} with the PEM of {@code privateKey.getEncoded()}, so the keyring behaves as with those bytes.
     *
     * @throws ValidationException if the key has no encoding, for example a key held in a hardware module
     */
    public Builder privateKey(PrivateKey privateKey) {
      throw new UnsupportedOperationException("not implemented yet");
    }

    public RawRsaKeyring build() {
      throw new UnsupportedOperationException("not implemented yet");
    }
  }
}
