// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keyrings;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnDecryptResponse;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.exceptions.CryptographicException;
import software.amazon.cryptography.materialproviders.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.materialproviders.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.internal.CanonicalEncryptionContext;
import software.amazon.cryptography.materialproviders.internal.EdkWrapping;
import software.amazon.cryptography.materialproviders.internal.KeyringNames;
import software.amazon.cryptography.materialproviders.internal.MaterialsAccess;
import software.amazon.cryptography.materialproviders.internal.MaterialsRules;
import software.amazon.cryptography.materialproviders.internal.primitives.AesGcm;
import software.amazon.cryptography.materialproviders.internal.primitives.Bytes;
import software.amazon.cryptography.materialproviders.internal.primitives.Randoms;

/**
 * Wraps data keys with a local AES-GCM key.
 *
 * <p>Each encrypted data key has provider id = key namespace, provider info =
 * {@code keyName || uint32 tag bits (128) || uint32 IV length (12) || IV}, and ciphertext = {@code AES-GCM ciphertext || tag};
 * the AAD is the canonical encryption context. Thread-safe.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/raw-aes-keyring.md">Raw AES keyring</a>.
 */
public final class RawAesKeyring implements Keyring {

  private static final int TAG_LENGTH = 16;
  private static final int IV_LENGTH = 12;

  private final String keyNamespace;
  private final String keyName;
  private final byte[] keyNameBytes;
  //= spec/framework/raw-aes-keyring.md#wrapping-key
  //# The wrapping key MUST be a secret value consisting of
  //# cryptographically secure pseudo-random bytes.
  //= spec/framework/raw-aes-keyring.md#wrapping-key
  //# It MUST be randomly
  //# generated from a cryptographically secure entropy source.
  private final SecretBytes wrappingKey;
  private final AesWrappingAlg wrappingAlg;

  private RawAesKeyring(Builder builder, byte[] keyNameBytes) {
    this.keyNamespace = builder.keyNamespace;
    this.keyName = builder.keyName;
    this.keyNameBytes = keyNameBytes;
    this.wrappingKey = builder.wrappingKey.copy();
    this.wrappingAlg = builder.wrappingAlg;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Recorded in each encrypted data key; with keyName identifies the wrapping key. Not {@code aws-kms}. */
  public String keyNamespace() {
    return keyNamespace;
  }

  /** Recorded in each encrypted data key; with keyNamespace identifies the wrapping key. */
  public String keyName() {
    return keyName;
  }

  /** Must match the wrapping key length. */
  public AesWrappingAlg wrappingAlg() {
    return wrappingAlg;
  }

  @Override
  //= spec/framework/raw-aes-keyring.md#onencrypt
  //= type=implication
  //# OnEncrypt MUST take [encryption materials](structures.md#encryption-
  //# materials) as input.
  public OnEncryptResponse onEncrypt(OnEncryptRequest request) {
    EncryptionMaterials materials = request.materials();
    EdkWrapping.Wrap<byte[]> wrap = this::wrap;
    EdkWrapping.GenerateAndWrap<byte[]> generateAndWrap = (suite, encryptionContext) -> {
      //= spec/framework/raw-aes-keyring.md#onencrypt
      //# If the [encryption materials](structures.md#encryption-materials) do
      //# not contain a plaintext data key, OnEncrypt MUST generate a random
      //# plaintext data key and set it on the [encryption materials]
      //# (structures.md#encryption-materials).
      byte[] plaintextMaterial = Randoms.generate(suite.dataKeyLength());
      EdkWrapping.Wrapped<byte[]> wrapped = wrap(plaintextMaterial, suite, encryptionContext);
      return wrapped.generated(plaintextMaterial);
    };
    EdkWrapping.WrapResult<byte[]> result = EdkWrapping.wrap(materials, wrap, generateAndWrap);
    EncryptedDataKey edk = EncryptedDataKey.builder()
        .keyProviderId(keyNamespace)
        .keyProviderInfo(providerInfo(result.info))
        .ciphertext(result.wrappedMaterial)
        .build();
    //= spec/framework/raw-aes-keyring.md#onencrypt
    //# The keyring MUST append the constructed encrypted data key to the
    //# encrypted data key list in the [encryption materials]
    //# (structures.md#encryption-materials).
    //= spec/framework/raw-aes-keyring.md#onencrypt
    //# OnEncrypt MUST output the modified [encryption materials]
    //# (structures.md#encryption-materials).
    return OnEncryptResponse.builder().materials(result.addTo(materials, edk)).build();
  }

  @Override
  //= spec/framework/raw-aes-keyring.md#ondecrypt
  //= type=implication
  //# OnDecrypt MUST take [decryption materials](structures.md#decryption-
  //# materials) and a list of [encrypted data keys]
  //# (structures.md#encrypted-data-key) as input.
  public OnDecryptResponse onDecrypt(OnDecryptRequest request) {
    DecryptionMaterials materials = request.materials();
    List<EncryptedDataKey> encryptedDataKeys = request.encryptedDataKeys();
    MaterialsRules.Decryption fields = MaterialsAccess.fields(materials);
    if (fields.plaintextDataKey != null || !MaterialsRules.isValid(fields)) {
      throw new InvalidMaterialsException("Keyring received decryption materials that already contain a plaintext data key.");
    }
    //= spec/framework/raw-aes-keyring.md#ondecrypt
    //= type=implication
    //# The keyring MUST attempt to serialize the [decryption materials'](structures.md#decryption-materials)
    //# [encryption context](structures.md#encryption-context-1) according to the [encryption context serialization specification](structures.md#serialization).
    //= spec/framework/raw-aes-keyring.md#ondecrypt
    //= type=implication
    //# If the keyring cannot
    //# serialize the encryption context, OnDecrypt MUST fail.
    CanonicalEncryptionContext.serialize(materials.encryptionContext());
    List<Throwable> errors = new ArrayList<>();
    //= spec/framework/raw-aes-keyring.md#ondecrypt
    //# The keyring MUST perform the following actions on each encrypted data
    //# key](structures.md#encrypted-data-key) in the input encrypted data
    //# key list, serially, until it successfully decrypts one.
    for (int i = 0; i < encryptedDataKeys.size(); i++) {
      EncryptedDataKey edk = encryptedDataKeys.get(i);
      byte[] info = edk.keyProviderInfo();
      if (edk.keyProviderId().equals(keyNamespace) && isValidProviderInfo(info)) {
        byte[] iv = Arrays.copyOfRange(info, keyNameBytes.length + 8, info.length);
        EdkWrapping.UnwrapResult<Void> unwrapped;
        try {
          unwrapped = EdkWrapping.unwrap(edk.ciphertext(), materials, (wrapped, suite, ec) -> unwrap(wrapped, suite, ec, iv));
        } catch (RuntimeException e) {
          errors.add(e);
          continue;
        }
        //= spec/framework/raw-aes-keyring.md#ondecrypt
        //# If a decryption succeeds, this keyring MUST add the resulting
        //# plaintext data key to the decryption materials and return the
        //# modified materials.
        return OnDecryptResponse.builder().materials(unwrapped.addTo(materials)).build();
      } else {
        errors.add(new ValidationException(KeyringNames.incorrectRawDataKeys(i, "AESKeyring", edk.keyProviderId())));
      }
    }
    //= spec/framework/raw-aes-keyring.md#ondecrypt
    //# If no decryption succeeds, the keyring MUST fail and MUST NOT modify
    //# the [decryption materials](structures.md#decryption-materials).
    throw new NoMatchingDataKeyException(
      "Raw AES Keyring was unable to decrypt any encrypted data key. The list of encountered Exceptions is avaible via `list`.",
      errors
    );
  }

  private EdkWrapping.Wrapped<byte[]> wrap(byte[] plaintextMaterial, AlgorithmSuite suite, EncryptionContext encryptionContext) {
    //= spec/framework/raw-aes-keyring.md#onencrypt
    //# The keyring MUST attempt to serialize the [encryption materials']
    //# (structures.md#encryption-materials) [encryption context]
    //# (structures.md#encryption-context-1) according to the
    //# [encryption context serialization specification](structures.md#serialization).
    //= spec/framework/raw-aes-keyring.md#onencrypt
    //= type=implication
    //# If the keyring cannot serialize
    //# the encryption context, OnEncrypt MUST fail.
    byte[] aad = CanonicalEncryptionContext.serialize(encryptionContext);
    byte[] iv = Randoms.generate(IV_LENGTH);
    byte[] key = wrappingKey.toByteArray();
    try {
      //= spec/framework/raw-aes-keyring.md#onencrypt
      //# The keyring MUST encrypt the plaintext data key in the [encryption
      //# materials](structures.md#encryption-materials) using AES-GCM.
      byte[][] encrypted = AesGcm.encrypt(TAG_LENGTH, key, iv, plaintextMaterial, aad);
      byte[] wrapped = new byte[encrypted[0].length + encrypted[1].length];
      System.arraycopy(encrypted[0], 0, wrapped, 0, encrypted[0].length);
      System.arraycopy(encrypted[1], 0, wrapped, encrypted[0].length, encrypted[1].length);
      return new EdkWrapping.Wrapped<>(wrapped, iv);
    } catch (GeneralSecurityException e) {
      throw new CryptographicException(e.getMessage(), e);
    } finally {
      Bytes.zero(key);
    }
  }

  private EdkWrapping.Unwrapped<Void> unwrap(byte[] wrapped, AlgorithmSuite suite, EncryptionContext encryptionContext, byte[] iv) {
    byte[] aad = CanonicalEncryptionContext.serialize(encryptionContext);
    if (wrapped.length < TAG_LENGTH) {
      throw new ValidationException("Insufficient data to decrypt.");
    }
    byte[] key = wrappingKey.toByteArray();
    try {
      byte[] plaintext = AesGcm.decrypt(
        TAG_LENGTH,
        key,
        iv,
        Arrays.copyOfRange(wrapped, 0, wrapped.length - TAG_LENGTH),
        Arrays.copyOfRange(wrapped, wrapped.length - TAG_LENGTH, wrapped.length),
        aad
      );
      if (plaintext.length != suite.dataKeyLength()) {
        Bytes.zero(plaintext);
        throw new ValidationException("Plaintext Data Key is not the expected length");
      }
      return new EdkWrapping.Unwrapped<>(plaintext, null);
    } catch (GeneralSecurityException e) {
      throw new CryptographicException(e.getMessage(), e);
    } finally {
      Bytes.zero(key);
    }
  }

  private byte[] providerInfo(byte[] iv) {
    return ByteBuffer.allocate(keyNameBytes.length + 8 + iv.length).put(keyNameBytes).putInt(TAG_LENGTH * 8).putInt(iv.length).put(iv).array();
  }

  // The key name, 128 tag bits, and a 12-byte IV, as this keyring writes them.
  private boolean isValidProviderInfo(byte[] info) {
    if (info.length != keyNameBytes.length + 8 + IV_LENGTH) {
      return false;
    }
    ByteBuffer buffer = ByteBuffer.wrap(info);
    byte[] name = new byte[keyNameBytes.length];
    buffer.get(name);
    //= spec/framework/raw-aes-keyring.md#authentication-tag-length
    //= type=implication
    //# This value MUST match the authentication tag length of the keyring's
    //# configured wrapping algorithm
    //= spec/framework/raw-aes-keyring.md#iv-length
    //= type=implication
    //# This value MUST match the IV length of the keyring's
    //# configured wrapping algorithm
    return Arrays.equals(name, keyNameBytes) && buffer.getInt() == TAG_LENGTH * 8 && buffer.getInt() == IV_LENGTH;
  }

  /**
   * Not thread-safe.
   * Requires {@code keyNamespace}, {@code keyName}, {@code wrappingKey}, {@code wrappingAlg}.
   * {@link #build()} throws {@link ValidationException} for invalid settings.
   */
  //= spec/framework/raw-aes-keyring.md#initialization
  //= type=implication
  //# On keyring initialization, the caller MUST provide the following:
  public static final class Builder {

    private String keyNamespace;
    private String keyName;
    private SecretBytes wrappingKey;
    private AesWrappingAlg wrappingAlg;

    private Builder() {}

    /** Recorded in each encrypted data key; with keyName identifies the wrapping key. Not {@code aws-kms}. */
    public Builder keyNamespace(String keyNamespace) {
      this.keyNamespace = keyNamespace;
      return this;
    }

    /** Recorded in each encrypted data key; with keyNamespace identifies the wrapping key. */
    public Builder keyName(String keyName) {
      this.keyName = keyName;
      return this;
    }

    /** The AES key; {@link #build()} copies it. */
    public Builder wrappingKey(SecretBytes wrappingKey) {
      this.wrappingKey = wrappingKey;
      return this;
    }

    /** Must match the wrapping key length. */
    public Builder wrappingAlg(AesWrappingAlg wrappingAlg) {
      this.wrappingAlg = wrappingAlg;
      return this;
    }

    public RawAesKeyring build() {
      KeyringNames.requireSet(keyNamespace, "keyNamespace");
      KeyringNames.requireSet(keyName, "keyName");
      KeyringNames.requireSet(wrappingKey, "wrappingKey");
      KeyringNames.requireSet(wrappingAlg, "wrappingAlg");
      //= spec/framework/raw-aes-keyring.md#changelog
      //= type=implication
      //# Raw AES keyring MUST NOT accept a key namespace of "aws-kms".
      if (keyNamespace.equals("aws-kms")) {
        throw new ValidationException("keyNamespace must not be `aws-kms`");
      }
      KeyringNames.parseNamespace(keyNamespace);
      byte[] keyNameBytes = KeyringNames.parseName(keyName);
      int size = wrappingKey.length();
      //= spec/framework/raw-aes-keyring.md#wrapping-key
      //= type=implication
      //# The length
      //# of the wrapping key MUST be 128, 192, or 256.
      if (size != 16 && size != 24 && size != 32) {
        throw new ValidationException("Invalid wrapping key length");
      }
      if (size != keyLength(wrappingAlg)) {
        throw new ValidationException("Wrapping key length does not match specified wrapping algorithm");
      }
      return new RawAesKeyring(this, keyNameBytes);
    }

    private static int keyLength(AesWrappingAlg alg) {
      switch (alg) {
        case ALG_AES128_GCM_IV12_TAG16:
          return 16;
        case ALG_AES192_GCM_IV12_TAG16:
          return 24;
        default:
          return 32;
      }
    }
  }
}
