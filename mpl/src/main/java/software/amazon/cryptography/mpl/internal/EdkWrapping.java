// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import software.amazon.cryptography.mpl.AlgorithmSuite;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptedDataKey;
import software.amazon.cryptography.mpl.EncryptionContext;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.SecretBytes;
import software.amazon.cryptography.mpl.exceptions.CryptographicException;
import software.amazon.cryptography.mpl.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.primitives.AesGcm;
import software.amazon.cryptography.mpl.internal.primitives.Bytes;
import software.amazon.cryptography.mpl.internal.primitives.DigestAlgorithm;
import software.amazon.cryptography.mpl.internal.primitives.Hkdf;
import software.amazon.cryptography.mpl.internal.primitives.Randoms;

/**
 * How keyrings turn a data key into encrypted data key ciphertext, per EdkWrapping.dfy and IntermediateKeyWrapping.dfy.
 *
 * <p>Direct-wrapping suites (all ESDK suites) give the keyring the data key itself.
 * Intermediate-wrapping suites (the DBE suites) give it a fresh intermediate key instead: the ciphertext is
 * {@code AES-GCM(data key) || keyring-wrapped intermediate key}, and the intermediate key also yields the
 * per-EDK symmetric signing key.
 */
public final class EdkWrapping {

  private static final byte[] KEYWRAP_MAC_INFO = "AWS_MPL_INTERMEDIATE_KEYWRAP_MAC".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] KEYWRAP_ENC_INFO = "AWS_MPL_INTERMEDIATE_KEYWRAP_ENC".getBytes(StandardCharsets.US_ASCII);

  private EdkWrapping() {}

  /** Wraps key material the keyring is given. {@code T} carries keyring-specific results, such as an IV. */
  public interface Wrap<T> {
    Wrapped<T> wrap(byte[] plaintextMaterial, AlgorithmSuite suite, EncryptionContext encryptionContext);
  }

  /** Creates key material of the suite's key length and wraps it; a keyring may use a service to do both (KMS). */
  public interface GenerateAndWrap<T> {
    Generated<T> generateAndWrap(AlgorithmSuite suite, EncryptionContext encryptionContext);
  }

  /** Recovers key material the keyring wrapped; the result must have the suite's key length. */
  public interface Unwrap<T> {
    Unwrapped<T> unwrap(byte[] wrappedMaterial, AlgorithmSuite suite, EncryptionContext encryptionContext);
  }

  public static final class Wrapped<T> {

    final byte[] wrappedMaterial;
    final T info;

    public Wrapped(byte[] wrappedMaterial, T info) {
      this.wrappedMaterial = wrappedMaterial;
      this.info = info;
    }

    /** This result as the output of generating {@code plaintextMaterial} and wrapping it. */
    public Generated<T> generated(byte[] plaintextMaterial) {
      return new Generated<>(plaintextMaterial, wrappedMaterial, info);
    }
  }

  public static final class Generated<T> {

    final byte[] plaintextMaterial;
    final byte[] wrappedMaterial;
    final T info;

    public Generated(byte[] plaintextMaterial, byte[] wrappedMaterial, T info) {
      this.plaintextMaterial = plaintextMaterial;
      this.wrappedMaterial = wrappedMaterial;
      this.info = info;
    }
  }

  public static final class Unwrapped<T> {

    final byte[] unwrappedMaterial;
    final T info;

    public Unwrapped(byte[] unwrappedMaterial, T info) {
      this.unwrappedMaterial = unwrappedMaterial;
      this.info = info;
    }
  }

  /** The result of wrapping: a new data key if the materials had none, the EDK ciphertext, and a symmetric signing key for DBE suites. */
  public static final class WrapResult<T> {

    /** Null when the materials already held a data key. */
    public final byte[] plaintextDataKey;
    public final byte[] wrappedMaterial;
    /** Null for direct-wrapping suites. */
    public final byte[] symmetricSigningKey;
    public final T info;

    WrapResult(byte[] plaintextDataKey, byte[] wrappedMaterial, byte[] symmetricSigningKey, T info) {
      this.plaintextDataKey = plaintextDataKey;
      this.wrappedMaterial = wrappedMaterial;
      this.symmetricSigningKey = symmetricSigningKey;
      this.info = info;
    }

    /**
     * {@code materials} with the new data key (if any) and this keyring's encrypted data key added.
     * Zeroes this result's secret arrays.
     */
    public EncryptionMaterials addTo(EncryptionMaterials materials, EncryptedDataKey edk) {
      SecretBytes key = plaintextDataKey == null ? null : SecretBytes.copyOf(plaintextDataKey);
      SecretBytes signing = symmetricSigningKey == null ? null : SecretBytes.copyOf(symmetricSigningKey);
      EncryptionMaterials withKey = null;
      try {
        withKey = key == null ? materials : materials.withPlaintextDataKey(key);
        return signing == null ? withKey.withEncryptedDataKey(edk) : withKey.withEncryptedDataKey(edk, signing);
      } finally {
        if (withKey != null && withKey != materials) {
          withKey.destroy();
        }
        destroy(key);
        destroy(signing);
        zero(plaintextDataKey);
        zero(symmetricSigningKey);
      }
    }
  }

  public static final class UnwrapResult<T> {

    public final byte[] plaintextDataKey;
    /** Null for direct-wrapping suites. */
    public final byte[] symmetricSigningKey;
    public final T info;

    UnwrapResult(byte[] plaintextDataKey, byte[] symmetricSigningKey, T info) {
      this.plaintextDataKey = plaintextDataKey;
      this.symmetricSigningKey = symmetricSigningKey;
      this.info = info;
    }

    /** {@code materials} with the recovered data key (and symmetric signing key) added. Zeroes this result's secret arrays. */
    //= spec/framework/keyring-interface.md#decrypt-data-key
    //= type=implication
    //# If the encryption materials do contain a plaintext data key, OnDecrypt MUST NOT decrypt a data key.
    //# If the [decryption materials](structures.md#decryption-materials) do not include a plaintext data key,
    //# OnDecrypt MUST decrypt a data key.
    //#
    //# The decrypt data key MUST modify the following fields in the [decryption materials](structures.md#decryption-materials):
    //#
    //# - [Plaintext data key](structures.md#plaintext-data-key-1)
    //#
    //# To perform this behavior, the keyring attempts to retrieve a plaintext data key from the input list
    //# of [encrypted data keys](structures.md#encrypted-data-key).
    //#
    //# If the keyring is able to succesfully get at least one plaintext data key from any [encrypted data key](structures.md#encrypted-data-key)
    //# and the [decryption materials](structures.md#decryption-materials) still do not include a plaintext data key,
    //# it SHOULD set one resulting plaintext data key on the [decryption materials](structures.md#decryption-materials).
    public DecryptionMaterials addTo(DecryptionMaterials materials) {
      SecretBytes key = SecretBytes.copyOf(plaintextDataKey);
      SecretBytes signing = symmetricSigningKey == null ? null : SecretBytes.copyOf(symmetricSigningKey);
      try {
        return signing == null ? materials.withPlaintextDataKey(key) : materials.withPlaintextDataKey(key, signing);
      } finally {
        destroy(key);
        destroy(signing);
        zero(plaintextDataKey);
        zero(symmetricSigningKey);
      }
    }
  }

  private static void destroy(SecretBytes secret) {
    if (secret != null) {
      secret.destroy();
    }
  }

  private static void zero(byte[] secret) {
    if (secret != null) {
      Bytes.zero(secret);
    }
  }

  /** WrapEdkMaterial. */
  //= spec/framework/keyring-interface.md#generate-data-key
  //= type=implication
  //# If the [encryption materials](structures.md#encryption-materials) do not contain a plaintext data key,
  //# OnEncrypt MUST generate a data key.
  //# If the encryption materials contain a plaintext data key, OnEncrypt MUST NOT generate a data key.
  //#
  //# Generate Data Key MUST modify the following fields in the [encryption materials](structures.md#encryption-materials):
  //#
  //# - [plaintext data key](structures.md#plaintext-data-key)
  //#
  //# To perform this behavior, the keyring generates a [plaintext data key](structures.md#plaintext-data-key)
  //# and sets the resulting plaintext data key on the [encryption materials](structures.md#encryption-materials).
  //#
  //# The length of the output plaintext data key MUST be equal to the KDF input length of the [algorithm suite](algorithm-suites.md)
  //# specified in the [encryption materials](structures.md#encryption-materials).
  //# The value of the plaintext data key MUST consist of cryptographically secure (pseudo-)random bits.
  //#
  //# Note: If the keyring successfully performs this behavior, this means that the keyring MAY then
  //# perform the [Encrypt Data Key](#encrypt-data-key) behavior.
  //= spec/framework/keyring-interface.md#encrypt-data-key
  //= type=implication
  //# If the [encryption materials](structures.md#encryption-materials) contain a plaintext data key,
  //# OnEncrypt MUST encrypt a data key.
  //# If the encryption materials do not contain a plaintext data key, OnEncrypt MUST NOT encrypt a data key.
  //#
  //# Encrypt Data Key MUST modify the following fields in the [encryption materials](structures.md#encryption-materials):
  //#
  //# - [encrypted data keys](structures.md#encrypted-data-keys)
  public static <T> WrapResult<T> wrap(EncryptionMaterials materials, Wrap<T> wrap, GenerateAndWrap<T> generateAndWrap) {
    MaterialsRules.Encryption fields = MaterialsAccess.fields(materials);
    if (!MaterialsRules.isValid(fields)) {
      throw new InvalidMaterialsException("Invalid materials for encryption.");
    }
    AlgorithmSuite suite = fields.suite;
    EncryptionContext encryptionContext = EncryptionContext.copyOf(fields.encryptionContext);
    if (fields.plaintextDataKey != null) {
      byte[] plaintextDataKey = fields.plaintextDataKey.toByteArray();
      try {
        if (!suite.usesIntermediateKeyWrapping()) {
          Wrapped<T> direct = wrap.wrap(plaintextDataKey, suite, encryptionContext);
          return new WrapResult<>(null, direct.wrappedMaterial, null, direct.info);
        }
        Intermediate<T> intermediate = intermediateWrap(generateAndWrap, plaintextDataKey, suite, encryptionContext);
        return new WrapResult<>(null, intermediate.wrappedMaterial, intermediate.symmetricSigningKey, intermediate.info);
      } finally {
        Bytes.zero(plaintextDataKey);
      }
    }
    if (!suite.usesIntermediateKeyWrapping()) {
      Generated<T> generated = generateAndWrap.generateAndWrap(suite, encryptionContext);
      return new WrapResult<>(generated.plaintextMaterial, generated.wrappedMaterial, null, generated.info);
    }
    byte[] plaintextDataKey = Randoms.generate(suite.dataKeyLength());
    Intermediate<T> intermediate;
    try {
      intermediate = intermediateWrap(generateAndWrap, plaintextDataKey, suite, encryptionContext);
    } catch (RuntimeException e) {
      Bytes.zero(plaintextDataKey);
      throw e;
    }
    return new WrapResult<>(plaintextDataKey, intermediate.wrappedMaterial, intermediate.symmetricSigningKey, intermediate.info);
  }

  /** GetProviderWrappedMaterial: the part of an encrypted data key's ciphertext that the keyring wrapped. */
  public static byte[] providerWrappedMaterial(byte[] ciphertext, AlgorithmSuite suite) {
    if (!suite.usesIntermediateKeyWrapping()) {
      return ciphertext;
    }
    int encryptedPdkLength = suite.dataKeyLength() + suite.tagLength();
    if (ciphertext.length < encryptedPdkLength) {
      throw new ValidationException("Unable to deserialize Intermediate Key Wrapped material.");
    }
    return Arrays.copyOfRange(ciphertext, encryptedPdkLength, ciphertext.length);
  }

  /** UnwrapEdkMaterial. */
  public static <T> UnwrapResult<T> unwrap(byte[] wrappedMaterial, DecryptionMaterials materials, Unwrap<T> unwrap) {
    MaterialsRules.Decryption fields = MaterialsAccess.fields(materials);
    if (!MaterialsRules.isValid(fields)) {
      throw new InvalidMaterialsException("Invalid materials for decryption.");
    }
    AlgorithmSuite suite = fields.suite;
    EncryptionContext encryptionContext = EncryptionContext.copyOf(fields.encryptionContext);
    if (!suite.usesIntermediateKeyWrapping()) {
      Unwrapped<T> direct = unwrap.unwrap(wrappedMaterial, suite, encryptionContext);
      return new UnwrapResult<>(direct.unwrappedMaterial, null, direct.info);
    }
    int encryptedPdkLength = suite.dataKeyLength() + suite.tagLength();
    if (wrappedMaterial.length < encryptedPdkLength) {
      throw new InvalidMaterialsException("Invalid material for Intermediate Unwrapping");
    }
    byte[] encryptedPdk = Arrays.copyOfRange(wrappedMaterial, 0, encryptedPdkLength);
    byte[] providerWrappedIkm = Arrays.copyOfRange(wrappedMaterial, encryptedPdkLength, wrappedMaterial.length);
    Unwrapped<T> unwrapped = unwrap.unwrap(providerWrappedIkm, suite, encryptionContext);
    byte[][] keys = deriveKeys(unwrapped.unwrappedMaterial, suite);
    byte[] symmetricSigningKey = keys[0];
    byte[] pdkEncryptionKey = keys[1];
    try {
      byte[] aad = CanonicalEncryptionContext.serialize(encryptionContext);
      byte[] plaintextDataKey = AesGcm.decrypt(
        suite.tagLength(),
        pdkEncryptionKey,
        new byte[suite.ivLength()],
        Arrays.copyOfRange(encryptedPdk, 0, suite.dataKeyLength()),
        Arrays.copyOfRange(encryptedPdk, suite.dataKeyLength(), encryptedPdkLength),
        aad
      );
      return new UnwrapResult<>(plaintextDataKey, symmetricSigningKey, unwrapped.info);
    } catch (GeneralSecurityException e) {
      Bytes.zero(symmetricSigningKey);
      throw new CryptographicException(e.getMessage(), e);
    } finally {
      Bytes.zero(pdkEncryptionKey);
      Bytes.zero(unwrapped.unwrappedMaterial);
    }
  }

  private static final class Intermediate<T> {

    final byte[] wrappedMaterial;
    final byte[] symmetricSigningKey;
    final T info;

    Intermediate(byte[] wrappedMaterial, byte[] symmetricSigningKey, T info) {
      this.wrappedMaterial = wrappedMaterial;
      this.symmetricSigningKey = symmetricSigningKey;
      this.info = info;
    }
  }

  // IntermediateWrap: the keyring generates and wraps a fresh intermediate key; the data key is encrypted under a key derived from it.
  private static <T> Intermediate<T> intermediateWrap(
    GenerateAndWrap<T> generateAndWrap,
    byte[] plaintextDataKey,
    AlgorithmSuite suite,
    EncryptionContext encryptionContext
  ) {
    //= spec/framework/algorithm-suites.md#intermediate-key-wrapping
    //# - For each encrypted data key, a distinct `intermediate key` MUST be generated using cryptographically secure random bytes.
    Generated<T> generated = generateAndWrap.generateAndWrap(suite, encryptionContext);
    byte[][] keys = deriveKeys(generated.plaintextMaterial, suite);
    byte[] symmetricSigningKey = keys[0];
    byte[] pdkEncryptionKey = keys[1];
    try {
      byte[] aad = CanonicalEncryptionContext.serialize(encryptionContext);
      //= spec/framework/algorithm-suites.md#wrapped-plaintext-data-key
      //# The wrapped plaintext data key MUST be the result of the following AES GCM 256 Encrypt operation:
      byte[][] encrypted = AesGcm.encrypt(suite.tagLength(), pdkEncryptionKey, new byte[suite.ivLength()], plaintextDataKey, aad);
      //= spec/framework/algorithm-suites.md#intermediate-key-wrapping
      //# - The [EDK ciphertext](./structures.md#ciphertext) MUST be the following serialization:
      //
      //= spec/framework/algorithm-suites.md#wrapped-plaintext-data-key
      //= type=implication
      //# This value MUST be equal to the algorithm suite's encryption key length + 16.
      byte[] wrapped = new byte[encrypted[0].length + encrypted[1].length + generated.wrappedMaterial.length];
      System.arraycopy(encrypted[0], 0, wrapped, 0, encrypted[0].length);
      System.arraycopy(encrypted[1], 0, wrapped, encrypted[0].length, encrypted[1].length);
      System.arraycopy(generated.wrappedMaterial, 0, wrapped, encrypted[0].length + encrypted[1].length, generated.wrappedMaterial.length);
      return new Intermediate<>(wrapped, symmetricSigningKey, generated.info);
    } catch (GeneralSecurityException e) {
      Bytes.zero(symmetricSigningKey);
      throw new CryptographicException(e.getMessage(), e);
    } finally {
      Bytes.zero(pdkEncryptionKey);
      Bytes.zero(generated.plaintextMaterial);
    }
  }

  // {symmetric signing key, data key encryption key}: HKDF-SHA-512 extract with no salt, expanded with two labels.
  private static byte[][] deriveKeys(byte[] intermediateMaterial, AlgorithmSuite suite) {
    byte[] prk = Hkdf.extract(DigestAlgorithm.SHA_512, null, intermediateMaterial);
    try {
      return new byte[][] {
        //= spec/framework/algorithm-suites.md#intermediate-key-wrapping
        //# - For each encrypted data key, a [symmetric signing key](./structures.md#symmetric-signing-key) MUST be derived from the `intermediate key`
        //# using the key derivation algorithm in the algorithm suite, with the following specifics:
        Hkdf.expand(DigestAlgorithm.SHA_512, prk, KEYWRAP_MAC_INFO, suite.dataKeyLength()),
        //= spec/framework/algorithm-suites.md#intermediate-key-wrapping
        //# - For each encrypted data key, a `key encryption key` MUST be derived from the `intermediate key`
        //# using the key derivation algorithm in the algorithm suite, with the following specifics:
        Hkdf.expand(DigestAlgorithm.SHA_512, prk, KEYWRAP_ENC_INFO, suite.dataKeyLength()),
      };
    } finally {
      Bytes.zero(prk);
    }
  }
}
