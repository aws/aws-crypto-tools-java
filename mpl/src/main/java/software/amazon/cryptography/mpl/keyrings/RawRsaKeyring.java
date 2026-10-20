// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import software.amazon.cryptography.mpl.AlgorithmSuite;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptedDataKey;
import software.amazon.cryptography.mpl.EncryptionContext;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnDecryptResponse;
import software.amazon.cryptography.mpl.OnEncryptRequest;
import software.amazon.cryptography.mpl.OnEncryptResponse;
import software.amazon.cryptography.mpl.SecretBytes;
import software.amazon.cryptography.mpl.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.mpl.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.EdkWrapping;
import software.amazon.cryptography.mpl.internal.KeyringNames;
import software.amazon.cryptography.mpl.internal.MaterialsAccess;
import software.amazon.cryptography.mpl.internal.MaterialsRules;
import software.amazon.cryptography.mpl.internal.SecretBytesAccess;
import software.amazon.cryptography.mpl.internal.primitives.Bytes;
import software.amazon.cryptography.mpl.internal.primitives.Pem;
import software.amazon.cryptography.mpl.internal.primitives.Randoms;
import software.amazon.cryptography.mpl.internal.primitives.Rsa;

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
    this.keyNamespace = builder.keyNamespace;
    this.keyName = builder.keyName;
    this.keyNameBytes = keyNameBytes;
    this.paddingScheme = builder.paddingScheme;
    this.publicKey = builder.publicKey;
    this.privateKey = builder.privateKey;
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
  public OnEncryptResponse onEncrypt(OnEncryptRequest request) {
    EncryptionMaterials materials = request.materials();
    //= spec/framework/raw-rsa-keyring.md#onencrypt
    //= type=implication
    //# OnEncrypt MUST fail if this keyring does not have a specified [public
    //# key](#public-key).
    //= spec/framework/raw-rsa-keyring.md#onencrypt
    //= type=implication
    //# The keyring MUST NOT derive a public key from a
    //# specified [private key](#private-key).
    if (publicKey == null || publicKey.length == 0) {
      throw new ValidationException("A RawRSAKeyring without a public key cannot provide OnEncrypt");
    }
    EdkWrapping.Wrap<Void> wrap = this::wrap;
    EdkWrapping.GenerateAndWrap<Void> generateAndWrap = (suite, encryptionContext) -> {
      //= spec/framework/raw-rsa-keyring.md#onencrypt
      //# If the [encryption materials](structures.md#encryption-materials) do
      //# not contain a plaintext data key, OnEncrypt MUST generate a random
      //# plaintext data key and set it on the [encryption materials]
      //# (structures.md#encryption-materials).
      byte[] plaintextMaterial = Randoms.generate(suite.dataKeyLength());
      return wrap(plaintextMaterial, suite, encryptionContext).generated(plaintextMaterial);
    };
    EdkWrapping.WrapResult<Void> result = EdkWrapping.wrap(materials, wrap, generateAndWrap);
    //= spec/framework/raw-rsa-keyring.md#onencrypt
    //# If RSA encryption was successful, OnEncrypt MUST return the input
    //# [encryption materials](structures.md#encryption-materials), modified
    //# in the following ways:
    //# - The encrypted data key list has a new encrypted data key added,
    //#   constructed as follows:
    //= spec/framework/raw-rsa-keyring.md#onencrypt
    //#  -  The [key provider ID](structures.md#key-provider-id) field is
    //#     this keyring's [key namespace](keyring-interface.md#key-
    //#     namespace).
    //= spec/framework/raw-rsa-keyring.md#onencrypt
    //#  -  The [key provider information](structures.md#key-provider-
    //#     information) field is this keyring's [key name](keyring-
    //#     interface.md#key-name).
    //= spec/framework/raw-rsa-keyring.md#onencrypt
    //#  -  The [ciphertext](structures.md#ciphertext) field is the
    //#     ciphertext output by the RSA encryption of the plaintext data
    //#     key.
    return OnEncryptResponse.of(result.addTo(materials, EncryptedDataKey.of(keyNamespace, keyNameBytes.clone(), result.wrappedMaterial)));
  }

  @Override
  //= spec/framework/raw-rsa-keyring.md#ondecrypt
  //= type=implication
  //# OnDecrypt MUST take [decryption materials](structures.md#decryption-
  //# materials) and a list of [encrypted data keys]
  //# (structures.md#encrypted-data-key) as input.
  public OnDecryptResponse onDecrypt(OnDecryptRequest request) {
    DecryptionMaterials materials = request.materials();
    List<EncryptedDataKey> encryptedDataKeys = request.encryptedDataKeys();
    //= spec/framework/raw-rsa-keyring.md#ondecrypt
    //= type=implication
    //# OnDecrypt MUST fail if this keyring does not have a specified [private
    //# key](#private-key).
    if (privateKey == null || privateKey.length() == 0) {
      // "OnEncrypt" is the Dafny-based MPL's wording.
      throw new ValidationException("A RawRSAKeyring without a private key cannot provide OnEncrypt");
    }
    MaterialsRules.Decryption fields = MaterialsAccess.fields(materials);
    //= spec/framework/raw-rsa-keyring.md#ondecrypt
    //= type=implication
    //# If the decryption materials already contain a plaintext data key, the
    //# keyring MUST fail and MUST NOT modify the [decryption materials]
    //# (structures.md#decryption-materials).
    if (fields.plaintextDataKey != null || !MaterialsRules.isValid(fields)) {
      throw new InvalidMaterialsException("Keyring received decryption materials that already contain a plaintext data key.");
    }
    List<Throwable> errors = new ArrayList<>();
    //= spec/framework/raw-rsa-keyring.md#ondecrypt
    //# The keyring MUST attempt to decrypt the input encrypted data keys, in
    //# list order, until it successfully decrypts one.
    for (int i = 0; i < encryptedDataKeys.size(); i++) {
      EncryptedDataKey edk = encryptedDataKeys.get(i);
      if (shouldDecrypt(edk)) {
        EdkWrapping.UnwrapResult<Void> unwrapped;
        try {
          unwrapped = EdkWrapping.unwrap(edk.ciphertext(), materials, this::unwrap);
        } catch (RuntimeException e) {
          errors.add(e);
          continue;
        }
        //= spec/framework/raw-rsa-keyring.md#ondecrypt
        //# If any decryption succeeds, this keyring MUST immediately return the
        //# input [decryption materials](structures.md#decryption-materials),
        //# modified in the following ways:
        //= spec/framework/raw-rsa-keyring.md#ondecrypt
        //# - The output of RSA decryption is set as the decryption material's
        //#   plaintext data key.
        return OnDecryptResponse.of(unwrapped.addTo(materials));
      }
      errors.add(new ValidationException(KeyringNames.incorrectRawDataKeys(i, "RSAKeyring", edk.keyProviderId())));
    }
    //= spec/framework/raw-rsa-keyring.md#ondecrypt
    //# If no decryption succeeds, the keyring MUST fail and MUST NOT modify
    //# the [decryption materials](structures.md#decryption-materials).
    throw new NoMatchingDataKeyException(
      "Raw RSA Key was unable to decrypt any encrypted data key. The list of encountered Exceptions is available via `list`.",
      errors
    );
  }

  private EdkWrapping.Wrapped<Void> wrap(byte[] plaintextMaterial, AlgorithmSuite suite, EncryptionContext encryptionContext) {
    //= spec/framework/raw-rsa-keyring.md#onencrypt
    //# The keyring MUST attempt to encrypt the plaintext data key in the
    //# [encryption materials](structures.md#encryption-materials) using RSA.
    //# The keyring performs [RSA encryption](#rsa) with the
    //# following specifics:
    //= spec/framework/raw-rsa-keyring.md#onencrypt
    //# - This keyring's [padding scheme](#supported-padding-schemes) is the RSA padding
    //#   scheme.
    //= spec/framework/raw-rsa-keyring.md#onencrypt
    //# - This keyring's [public key](#public-key) is the RSA public key.
    //= spec/framework/raw-rsa-keyring.md#onencrypt
    //# - The plaintext data key is the plaintext input to RSA encryption.
    return new EdkWrapping.Wrapped<>(Rsa.encrypt(paddingScheme, publicKey, plaintextMaterial), null);
  }

  private EdkWrapping.Unwrapped<Void> unwrap(byte[] wrappedMaterial, AlgorithmSuite suite, EncryptionContext encryptionContext) {
    byte[] plaintext = SecretBytesAccess.apply(privateKey, key -> Rsa.decrypt(paddingScheme, key, wrappedMaterial));
    if (plaintext.length != suite.dataKeyLength()) {
      Bytes.zero(plaintext);
      throw new ValidationException("Invalid plaintext length.");
    }
    return new EdkWrapping.Unwrapped<>(plaintext, null);
  }

  // The provider info must be the key name's UTF-8 bytes exactly.
  //= spec/framework/raw-rsa-keyring.md#ondecrypt
  //= type=implication
  //# For each encrypted data key, the keyring MUST attempt to decrypt the
  //# encrypted data key into plaintext using RSA if and only if the
  //# following is true:
  private boolean shouldDecrypt(EncryptedDataKey edk) {
    byte[] info = edk.keyProviderInfo();
    return (
      //= spec/framework/raw-rsa-keyring.md#ondecrypt
      //= type=implication
      //# - The encrypted data key's [key provider information]
      //#   (structures.md#key-provider-information). has a value equal to
      //#   this keyring's [key name](keyring-interface.md#key-name).
      Arrays.equals(info, keyNameBytes) &&
      //= spec/framework/raw-rsa-keyring.md#ondecrypt
      //= type=implication
      //# - The encrypted data key's [key provider ID](structures.md#key-
      //#   provider-id) has a value equal to this keyring's [key namespace]
      //#   (keyring-interface.md#key-namespace).
      edk.keyProviderId().equals(keyNamespace) &&
      edk.ciphertext().length > 0
    );
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
      this.publicKey = publicKey == null ? null : Pem.publicKey(publicKey, "publicKey");
      return this;
    }

    /**
     * {@link #privateKey(SecretBytes)} with the PEM of {@code privateKey.getEncoded()}, so the keyring behaves as with those bytes.
     *
     * @throws ValidationException if the key has no encoding, for example a key held in a hardware module
     */
    public Builder privateKey(PrivateKey privateKey) {
      this.privateKey = privateKey == null ? null : Pem.privateKey(privateKey, "privateKey");
      return this;
    }

    public RawRsaKeyring build() {
      KeyringNames.requireSet(keyNamespace, "keyNamespace");
      KeyringNames.requireSet(keyName, "keyName");
      KeyringNames.requireSet(paddingScheme, "paddingScheme");
      //= spec/framework/raw-rsa-keyring.md#changelog
      //= type=implication
      //# Raw RSA keyring MUST NOT accept a key namespace of "aws-kms".
      if (keyNamespace.equals("aws-kms")) {
        throw new ValidationException("keyNamespace must not be `aws-kms`");
      }
      if (publicKey == null && privateKey == null) {
        throw new ValidationException("A publicKey or a privateKey is required");
      }
      KeyringNames.parseNamespace(keyNamespace);
      return new RawRsaKeyring(this, KeyringNames.parseName(keyName));
    }
  }
}
