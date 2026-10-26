// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.exceptions.CryptographicException;
import software.amazon.cryptography.materialproviders.exceptions.ServiceException;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.internal.primitives.AesGcm;
import software.amazon.cryptography.materialproviders.internal.primitives.Bytes;
import software.amazon.cryptography.materialproviders.internal.primitives.DigestAlgorithm;
import software.amazon.cryptography.materialproviders.internal.primitives.Ecdh;
import software.amazon.cryptography.materialproviders.internal.primitives.KdfCounterMode;
import software.amazon.cryptography.materialproviders.internal.primitives.Randoms;
import software.amazon.cryptography.materialproviders.keyrings.EcdhCurveSpec;

/**
 * EDK wrapping for the ECDH keyrings, per EcdhEdkWrapping.dfy, and their provider info, per RawECDHKeyring.dfy.
 *
 * <p>The wrapping key comes from KDF in counter mode (HMAC-SHA-384) over the shared secret, a random 32-byte salt,
 * and the fixed info, which binds the curve, both compressed public keys, the keyring version, and the encryption context.
 * Its 64 bytes are a commitment key and an AES-256-GCM key.
 * The wrapped material is {@code salt || commitment key || AES-GCM ciphertext || tag}, encrypted with a zero IV and the fixed info as AAD;
 * the zero IV is safe because each salt gives a new key.
 */
public final class EcdhEdkWrapping {

  public static final String RAW_PROVIDER_ID = "raw-ecdh";
  public static final String KMS_PROVIDER_ID = "aws-kms-ecdh";

  private static final byte KEYRING_VERSION = 0x01;
  private static final byte[] KDF_LABEL = "ecdh-key-derivation".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] PRF_NAME = "HMAC_SHA384".getBytes(StandardCharsets.US_ASCII);
  private static final int SALT_LENGTH = 32;
  private static final int COMMITMENT_KEY_LENGTH = 32;
  private static final int DERIVED_LENGTH = 64;
  private static final int WRAPPED_KEY_INDEX = SALT_LENGTH + COMMITMENT_KEY_LENGTH;
  // CIPHERTEXT_WRAPPED_MATERIAL_INDEX of Constants.dfy; shorter material fails with its own message.
  private static final int MIN_WRAPPED_LENGTH = 68;
  //= spec/framework/raw-ecdh-keyring.md#data-key-wrapping
  //= type=implication
  //# - MUST use an authentication tag byte of length 16.
  private static final int TAG_LENGTH = 16;
  private static final int IV_LENGTH = 12;
  // The field lengths of P-256, P-384, and P-521: the lengths of their ECDH shared secrets.
  private static final int[] SHARED_SECRET_LENGTHS = { 32, 48, 66 };
  /** The primitives library's message for a KDF input it rejects: a shared secret of the wrong length, which only KMS can return. */
  public static final String KDF_INPUT_INVALID = "Kdf in Counter Mode input is invalid.";
  // Version, two uint32 lengths, and two compressed points of P-256, P-384, or P-521.
  private static final int[] PROVIDER_INFO_LENGTHS = { 75, 107, 143 };

  private EcdhEdkWrapping() {}

  /** The compressed public keys an encrypted data key's provider info names. */
  public static final class ProviderInfo {

    public final byte[] recipientPublicKey;
    public final byte[] senderPublicKey;

    ProviderInfo(byte[] recipientPublicKey, byte[] senderPublicKey) {
      this.recipientPublicKey = recipientPublicKey;
      this.senderPublicKey = senderPublicKey;
    }
  }

  /**
   * Fails for a key that {@link Ecdh#validatePublicKey} returned false for: the only such keys are the curve points with x = 0.
   * No private key for them is known, so no honest party holds one, and data wrapped to one could not be decrypted.
   *
   * @param validatePublicKeyResult the result of {@link Ecdh#validatePublicKey} for the key
   * @param name the key's role, for the message
   */
  public static void requireValidPublicKey(boolean validatePublicKeyResult, String name) {
    if (!validatePublicKeyResult) {
      throw new ValidationException("Invalid " + name + ": a point with x coordinate 0 is not accepted.");
    }
  }

  /** {@code version || uint32 length || recipient's compressed key || uint32 length || sender's compressed key}. */
  public static byte[] providerInfo(byte[] senderPublicKey, byte[] recipientPublicKey) {
    return ByteBuffer
      .allocate(1 + 4 + recipientPublicKey.length + 4 + senderPublicKey.length)
      .put(KEYRING_VERSION)
      .putInt(recipientPublicKey.length)
      .put(recipientPublicKey)
      .putInt(senderPublicKey.length)
      .put(senderPublicKey)
      .array();
  }

  /**
   * Reads the provider info as the ECDH keyrings' decrypt filters do.
   * The sender key is everything after its length field; the field's value is not checked.
   */
  public static ProviderInfo parseProviderInfo(byte[] info) {
    if (Arrays.stream(PROVIDER_INFO_LENGTHS).noneMatch(length -> length == info.length)) {
      throw new ValidationException("EDK ProviderInfo longer than expected");
    }
    //= spec/framework/raw-ecdh-keyring.md#ondecrypt
    //# - The deserialized version value in the [key provider information](#key-provider-information) MUST match `0x01`.
    if (info[0] != KEYRING_VERSION) {
      throw new ValidationException("Incorrect Keyring version found in provider info.");
    }
    long recipientEnd = 5 + (ByteBuffer.wrap(info, 1, 4).getInt() & 0xFFFFFFFFL);
    if (recipientEnd + 4 >= info.length) {
      throw new ValidationException("Key Provider Info Serialization Error. Serialized length less than expected.");
    }
    return new ProviderInfo(Arrays.copyOfRange(info, 5, (int) recipientEnd), Arrays.copyOfRange(info, (int) recipientEnd + 4, info.length));
  }

  /** SerializeFixedInfo with this keyring version. Throws if the encryption context cannot be serialized. */
  public static byte[] fixedInfo(EcdhCurveSpec curve, byte[] senderPublicKey, byte[] recipientPublicKey, EncryptionContext encryptionContext) {
    byte[] curveName = curveName(curve);
    //= spec/framework/raw-ecdh-keyring.md#ondecrypt
    //= type=implication
    //# If the keyring cannot
    //# serialize the encryption context, OnDecrypt MUST fail.
    byte[] context = CanonicalEncryptionContext.serialize(encryptionContext);
    //= spec/framework/key-agreement-schemas.md#key-derivation
    //= type=implication
    //# The FixedInfo field MUST be serialized in the following order:
    return ByteBuffer
      .allocate(KDF_LABEL.length + curveName.length + PRF_NAME.length + senderPublicKey.length + recipientPublicKey.length + 1 + context.length + 5)
      //= spec/framework/key-agreement-schemas.md#key-derivation
      //= type=implication
      //# - MUST be the UTF8 encoded string "ecdh-key-derivation"
      .put(KDF_LABEL)
      //= spec/framework/key-agreement-schemas.md#key-derivation
      //= type=implication
      //# - MUST use a null byte concatenating all the fixed info fields.
      .put((byte) 0)
      //= spec/framework/key-agreement-schemas.md#key-derivation
      //= type=implication
      //# - MUST be the UTF8 encoded string of the configured curve specification
      .put(curveName)
      .put((byte) 0)
      //= spec/framework/key-agreement-schemas.md#key-derivation
      //= type=implication
      //# - MUST be the UTF8 encoded string of the configured Key Derivation Method used
      .put(PRF_NAME)
      .put((byte) 0)
      //= spec/framework/key-agreement-schemas.md#key-derivation
      //= type=implication
      //# - MUST be A concatenation of the static public keys used by the parties
      //#  in the format of sender followed by receiver
      .put(senderPublicKey)
      .put(recipientPublicKey)
      .put((byte) 0)
      //= spec/framework/key-agreement-schemas.md#key-derivation
      //= type=implication
      //# - MUST use the keyring version found in the key provider information.
      .put(KEYRING_VERSION)
      .put((byte) 0)
      //= spec/framework/key-agreement-schemas.md#key-derivation
      //= type=implication
      //# - MUST be The canonicalized encryption context found in the [encryption materials](structures.md#encryption-materials)
      .put(context)
      .array();
  }

  /** Wraps key material under {@code sharedSecret}, which the caller keeps and zeroes. */
  public static EdkWrapping.Wrap<Void> wrap(byte[] sharedSecret, byte[] fixedInfo) {
    return (plaintextMaterial, suite, encryptionContext) -> new EdkWrapping.Wrapped<>(wrap(sharedSecret, fixedInfo, plaintextMaterial), null);
  }

  /** Generates key material of the suite's key length and wraps it under {@code sharedSecret}. */
  public static EdkWrapping.GenerateAndWrap<Void> generateAndWrap(byte[] sharedSecret, byte[] fixedInfo) {
    return (suite, encryptionContext) -> {
      //= spec/framework/raw-ecdh-keyring.md#data-key-wrapping
      //= type=implication
      //# If the [encryption materials](structures.md#encryption-materials) do not contain a plaintext data key,
      //# OnEncrypt MUST generate a random plaintext data key.
      byte[] plaintextMaterial = Randoms.generate(suite.dataKeyLength());
      try {
        return new EdkWrapping.Generated<>(plaintextMaterial, wrap(sharedSecret, fixedInfo, plaintextMaterial), null);
      } catch (RuntimeException e) {
        Bytes.zero(plaintextMaterial);
        throw e;
      }
    };
  }

  /** Unwraps key material that names {@code info}'s keys, under {@code sharedSecret}, which the caller keeps and zeroes. */
  public static EdkWrapping.Unwrap<Void> unwrap(byte[] sharedSecret, EcdhCurveSpec curve, ProviderInfo info) {
    return (wrapped, suite, encryptionContext) -> {
      if (wrapped.length <= MIN_WRAPPED_LENGTH) {
        throw new ValidationException("Received ciphertext is shorter than expected.");
      }
      int keyLength = suite.dataKeyLength();
      if (wrapped.length <= WRAPPED_KEY_INDEX + keyLength) {
        throw new ValidationException("Received EDK Ciphertext of incorrect length3.");
      }
      byte[] salt = Arrays.copyOfRange(wrapped, 0, SALT_LENGTH);
      byte[] commitmentKey = Arrays.copyOfRange(wrapped, SALT_LENGTH, WRAPPED_KEY_INDEX);
      byte[] wrappedKey = Arrays.copyOfRange(wrapped, WRAPPED_KEY_INDEX, WRAPPED_KEY_INDEX + keyLength);
      byte[] tag = Arrays.copyOfRange(wrapped, WRAPPED_KEY_INDEX + keyLength, wrapped.length);
      byte[] fixedInfo = fixedInfo(curve, info.senderPublicKey, info.recipientPublicKey, encryptionContext);
      byte[] derived = derive(sharedSecret, fixedInfo, salt);
      byte[] key = Arrays.copyOfRange(derived, COMMITMENT_KEY_LENGTH, DERIVED_LENGTH);
      try {
        //= spec/framework/raw-ecdh-keyring.md#ondecrypt
        //# The keyring MUST check that the calculated Commitment Key
        //# from the key derivation step is equal to the deserialized commitment key
        //# found in the encrypted data key.
        if (!MessageDigest.isEqual(Arrays.copyOf(derived, COMMITMENT_KEY_LENGTH), commitmentKey)) {
          throw new CryptographicException("Commitment keys do not match");
        }
        // The message of the primitives library's AESDecrypt input check, which the Dafny-based MPL reached here.
        if (tag.length != TAG_LENGTH) {
          throw new ValidationException("Request does not match algorithm.");
        }
        //= spec/framework/raw-ecdh-keyring.md#data-key-unwrapping
        //# The keyring MUST decrypt the encrypted data key with the shared wrapping key using `AES-GCM-256` with the following inputs:

        //= spec/framework/raw-ecdh-keyring.md#data-key-unwrapping
        //# - It MUST use the shared wrapping key as the AES-GCM cipher key.

        //= spec/framework/raw-ecdh-keyring.md#data-key-unwrapping
        //# - It MUST use the `encrypted key` obtained from deserialization as the AES-GCM input ciphertext.

        //= spec/framework/raw-ecdh-keyring.md#data-key-unwrapping
        //# - It MUST use the `authentication tag` obtained from deserialization as the AES-GCM input authentication tag.

        //= spec/framework/raw-ecdh-keyring.md#data-key-unwrapping
        //# - It MUST use a zeroed out 12 byte IV

        //= spec/framework/raw-ecdh-keyring.md#data-key-unwrapping
        //# - MUST use the serialized [AAD](#branch-key-wrapping-and-unwrapping-aad) concatenated
        //#   with the `FixedInfo` used as part of the key derivation step concatenated with the keyring version found
        //#   in the key provider information.
        return new EdkWrapping.Unwrapped<>(AesGcm.decrypt(TAG_LENGTH, key, new byte[IV_LENGTH], wrappedKey, tag, fixedInfo), null);
      } catch (GeneralSecurityException e) {
        throw new CryptographicException(e.getMessage(), e);
      } finally {
        Bytes.zero(derived);
        Bytes.zero(key);
      }
    };
  }

  private static byte[] wrap(byte[] sharedSecret, byte[] fixedInfo, byte[] plaintextMaterial) {
    //= spec/framework/key-agreement-schemas.md#key-derivation
    //# Before deriving a shared wrapping key, the keyring MUST generate a 32 byte random salt value.

    //= spec/framework/key-agreement-schemas.md#key-derivation
    //# If the keyring fails to generate a random value, the operation MUST fail.
    byte[] salt = Randoms.generate(SALT_LENGTH);
    //= spec/framework/raw-ecdh-keyring.md#onencrypt
    //# The keyring MUST derive a data key according to the construction
    //# outlined by the [key agreement schemas](./key-agreement-schemas.md#key-derivation)

    //= spec/framework/raw-ecdh-keyring.md#onencrypt
    //# If the Key Derivation step fails, the keyring MUST fail.
    byte[] derived = derive(sharedSecret, fixedInfo, salt);
    //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
    //# The keyring MUST use the last 32 bytes as the Shared Wrapping Key.
    byte[] key = Arrays.copyOfRange(derived, COMMITMENT_KEY_LENGTH, DERIVED_LENGTH);
    try {
      //= spec/framework/raw-ecdh-keyring.md#data-key-wrapping
      //= type=implication
      //# The keyring MUST encrypt the plaintext data key
      //# using AES-GCM and use the shared wrapping key as the wrapping key.

      //= spec/framework/raw-ecdh-keyring.md#data-key-wrapping
      //# The keyring MUST encrypt a plaintext data key
      //# using `AES-GCM-256` with the following inputs:

      //= spec/framework/raw-ecdh-keyring.md#data-key-wrapping
      //# - MUST use the shared wrapping key as the AES-GCM cipher key.

      //= spec/framework/raw-ecdh-keyring.md#data-key-wrapping
      //# - MUST use the plain text data key that will be wrapped by the shared wrapping key as the AES-GCM message.

      //= spec/framework/raw-ecdh-keyring.md#data-key-wrapping
      //# - It MUST use a zeroed out 12 byte IV

      //= spec/framework/raw-ecdh-keyring.md#data-key-wrapping
      //# - MUST use the serialized [AAD](#branch-key-wrapping-and-unwrapping-aad) concatenated
      //#   with the `FixedInfo` used as part of the key derivation step concatenated with the keyring version found
      //#   in the key provider information.
      byte[][] encrypted = AesGcm.encrypt(TAG_LENGTH, key, new byte[IV_LENGTH], plaintextMaterial, fixedInfo);
      return ByteBuffer
        .allocate(WRAPPED_KEY_INDEX + encrypted[0].length + encrypted[1].length)
        .put(salt)
        //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
        //# The keyring MUST use the first 32 bytes as the Commitment Key.
        .put(derived, 0, COMMITMENT_KEY_LENGTH)
        .put(encrypted[0])
        .put(encrypted[1])
        .array();
    } catch (GeneralSecurityException e) {
      throw new CryptographicException(e.getMessage(), e);
    } finally {
      Bytes.zero(derived);
      Bytes.zero(key);
    }
  }

  //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
  //= type=implication
  //# The keyring MUST derive a shared wrapping key according to the construction
  //# outlined by the [key agreement schemes](./key-agreement-schemas.md#key-derivation)

  //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
  //= type=implication
  //# If they Key Derivation step succeeds it MUST produce
  //# keying material with a length of 64 bytes.
  // DeriveSharedKeyingMaterial: 64 bytes, the commitment key then the wrapping key.
  // Of KdfCtr.dfy's input checks only the shared secret length can fail: KMS DeriveSharedSecret may return any length.
  private static byte[] derive(byte[] sharedSecret, byte[] fixedInfo, byte[] salt) {
    if (Arrays.stream(SHARED_SECRET_LENGTHS).noneMatch(length -> length == sharedSecret.length)) {
      throw new ServiceException(KDF_INPUT_INVALID);
    }
    //= spec/framework/key-agreement-schemas.md#key-derivation
    //= type=implication
    //# - MUST use the derived shared secret, Z

    //= spec/framework/key-agreement-schemas.md#key-derivation
    //= type=implication
    //# - L: MUST be a length of 512 bits

    //= spec/framework/key-agreement-schemas.md#key-derivation
    //= type=implication
    //# - salt: MUST be a random 32 byte string
    return KdfCounterMode.derive(DigestAlgorithm.SHA_384, sharedSecret, KdfCounterMode.fixedInput(fixedInfo, salt, DERIVED_LENGTH), DERIVED_LENGTH);
  }

  private static byte[] curveName(EcdhCurveSpec curve) {
    switch (curve) {
      case ECC_NIST_P256:
        return "p256".getBytes(StandardCharsets.US_ASCII);
      case ECC_NIST_P384:
        return "p384".getBytes(StandardCharsets.US_ASCII);
      case ECC_NIST_P521:
        return "p521".getBytes(StandardCharsets.US_ASCII);
      default:
        // Keyrings reject SM2 when they are built.
        throw new IllegalArgumentException("no ECDH keyring curve " + curve);
    }
  }
}
