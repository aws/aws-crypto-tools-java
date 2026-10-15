// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.primitives;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Objects;
import software.amazon.cryptography.mpl.internal.primitives.AesGcm;
import software.amazon.cryptography.materialproviders.internal.Buffers;
import software.amazon.cryptography.mpl.internal.primitives.Bytes;
import software.amazon.cryptography.mpl.internal.primitives.Digests;
import software.amazon.cryptography.mpl.internal.primitives.Hkdf;
import software.amazon.cryptography.mpl.internal.primitives.KdfCounterMode;
import software.amazon.cryptography.mpl.internal.primitives.Randoms;
import software.amazon.cryptography.primitives.model.AESDecryptInput;
import software.amazon.cryptography.primitives.model.AESEncryptInput;
import software.amazon.cryptography.primitives.model.AESEncryptOutput;
import software.amazon.cryptography.primitives.model.AesKdfCtrInput;
import software.amazon.cryptography.primitives.model.AwsCryptographicPrimitivesError;
import software.amazon.cryptography.primitives.model.CryptoConfig;
import software.amazon.cryptography.mpl.internal.primitives.DigestAlgorithm;
import software.amazon.cryptography.primitives.model.DigestInput;
import software.amazon.cryptography.primitives.model.GenerateRandomBytesInput;
import software.amazon.cryptography.primitives.model.HMacInput;
import software.amazon.cryptography.primitives.model.HkdfExpandInput;
import software.amazon.cryptography.primitives.model.HkdfExtractInput;
import software.amazon.cryptography.primitives.model.HkdfInput;
import software.amazon.cryptography.primitives.model.KdfCtrInput;
import software.amazon.cryptography.primitives.model.OpaqueError;

/**
 * Cryptographic primitives used by the Material Providers Library.
 * Input checks and their messages follow the Dafny-based MPL (AwsCryptographyPrimitives),
 * so callers see the same failures.
 */
public class AtomicPrimitives {

  // Dafny's INT32_MAX_LIMIT; inputs must be strictly shorter.
  private static final long INT32_MAX_LIMIT = Integer.MAX_VALUE;

  // CryptoConfig has no fields; the builder only requires that one is passed.
  protected AtomicPrimitives(BuilderImpl builder) {}

  public static Builder builder() {
    return new BuilderImpl();
  }

  public ByteBuffer GenerateRandomBytes(GenerateRandomBytesInput input) {
    try {
      return ByteBuffer.wrap(Randoms.generate(input.length()));
    } catch (Exception e) {
      throw OpaqueError.builder().obj(e).build();
    }
  }

  public ByteBuffer Digest(DigestInput input) {
    return ByteBuffer.wrap(Digests.digest(alg(input.digestAlgorithm()), Buffers.toArray(input.message())));
  }

  public ByteBuffer HMac(HMacInput input) {
    byte[] key = Buffers.toArray(input.key());
    try {
      if (key.length == 0) {
        throw error("Key MUST NOT be 0 bytes.");
      }
      if (input.message().limit() >= INT32_MAX_LIMIT) {
        throw error("Message over INT32_MAX_LIMIT");
      }
      return ByteBuffer.wrap(Digests.hmac(alg(input.digestAlgorithm()), key, Buffers.toArray(input.message())));
    } finally {
      Bytes.zero(key);
    }
  }

  public ByteBuffer HkdfExtract(HkdfExtractInput input) {
    if (isEmpty(input.salt()) || input.ikm().limit() >= INT32_MAX_LIMIT) {
      throw error("HKDF Extract needs a salt and reasonable ikm.");
    }
    byte[] ikm = Buffers.toArray(input.ikm());
    try {
      return ByteBuffer.wrap(Hkdf.extract(alg(input.digestAlgorithm()), toArrayOrNull(input.salt()), ikm));
    } finally {
      Bytes.zero(ikm);
    }
  }

  public ByteBuffer HkdfExpand(HkdfExpandInput input) {
    DigestAlgorithm algorithm = alg(input.digestAlgorithm());
    if (
      !validHkdfLength(algorithm, input.expectedLength()) ||
      input.info().limit() >= INT32_MAX_LIMIT ||
      input.prk().limit() != Digests.length(algorithm)
    ) {
      throw error("HKDF Expand needs valid input.");
    }
    byte[] prk = Buffers.toArray(input.prk());
    try {
      return ByteBuffer.wrap(Hkdf.expand(algorithm, prk, Buffers.toArray(input.info()), input.expectedLength()));
    } finally {
      Bytes.zero(prk);
    }
  }

  public ByteBuffer Hkdf(HkdfInput input) {
    if (
      !validHkdfLength(alg(input.digestAlgorithm()), input.expectedLength()) ||
      isEmpty(input.salt()) ||
      input.info().limit() >= INT32_MAX_LIMIT ||
      input.ikm().limit() >= INT32_MAX_LIMIT
    ) {
      throw error("Wrapped Hkdf input is invalid.");
    }
    byte[] ikm = Buffers.toArray(input.ikm());
    try {
      return ByteBuffer.wrap(
        Hkdf.hkdf(
          alg(input.digestAlgorithm()),
          toArrayOrNull(input.salt()),
          ikm,
          Buffers.toArray(input.info()),
          input.expectedLength()
        )
      );
    } finally {
      Bytes.zero(ikm);
    }
  }

  /**
   * KDF in counter mode (NIST SP 800-108) with HMAC-SHA-256 or HMAC-SHA-384.
   * Accepts only the parameter sets the library uses: ikm of 32, 48, or 66 bytes,
   * a nonce of 16 or 32 bytes, and an output of 32 or 64 bytes.
   */
  public ByteBuffer KdfCounterMode(KdfCtrInput input) {
    int ikmLength = input.ikm().limit();
    ByteBuffer nonce = input.nonce();
    int length = input.expectedLength();
    if (
      !(alg(input.digestAlgorithm()) == DigestAlgorithm.SHA_256 || alg(input.digestAlgorithm()) == DigestAlgorithm.SHA_384) ||
      !(ikmLength == 32 || ikmLength == 48 || ikmLength == 66) ||
      nonce == null ||
      !(nonce.limit() == 16 || nonce.limit() == 32) ||
      !(length == 32 || length == 64)
    ) {
      throw error("Kdf in Counter Mode input is invalid.");
    }
    byte[] label = input.purpose() == null ? new byte[0] : Buffers.toArray(input.purpose());
    // 4-byte counter, 1-byte separator, 4-byte length, label, and context must fit Dafny's int32 bound.
    if (9L + label.length + nonce.limit() >= INT32_MAX_LIMIT) {
      throw error("Input Length exceeds INT32_MAX_LIMIT");
    }
    byte[] ikm = Buffers.toArray(input.ikm());
    try {
      return ByteBuffer.wrap(
        KdfCounterMode.derive(
          alg(input.digestAlgorithm()),
          ikm,
          KdfCounterMode.fixedInput(label, Buffers.toArray(nonce), length),
          length
        )
      );
    } finally {
      Bytes.zero(ikm);
    }
  }

  /** Always throws: the library has no AES-based KDF in counter mode. */
  public ByteBuffer AesKdfCounterMode(AesKdfCtrInput input) {
    throw error("Implement");
  }

  public AESEncryptOutput AESEncrypt(AESEncryptInput input) {
    if (
      input.iv().limit() != input.encAlg().ivLength() ||
      input.key().limit() != input.encAlg().keyLength()
    ) {
      throw error("Request does not match algorithm.");
    }
    byte[] key = Buffers.toArray(input.key());
    // The message is often a data key, so this copy is a secret too.
    byte[] plaintext = Buffers.toArray(input.msg());
    try {
      byte[][] output = AesGcm.encrypt(
        input.encAlg().tagLength(),
        key,
        Buffers.toArray(input.iv()),
        plaintext,
        Buffers.toArray(input.aad())
      );
      return AESEncryptOutput
        .builder()
        .cipherText(ByteBuffer.wrap(output[0]))
        .authTag(ByteBuffer.wrap(output[1]))
        .build();
    } catch (GeneralSecurityException e) {
      throw opaque(e);
    } finally {
      Bytes.zero(key);
      Bytes.zero(plaintext);
    }
  }

  public ByteBuffer AESDecrypt(AESDecryptInput input) {
    if (
      input.key().limit() != input.encAlg().keyLength() ||
      input.iv().limit() != input.encAlg().ivLength() ||
      input.authTag().limit() != input.encAlg().tagLength()
    ) {
      throw error("Request does not match algorithm.");
    }
    byte[] key = Buffers.toArray(input.key());
    try {
      return ByteBuffer.wrap(
        AesGcm.decrypt(
          input.encAlg().tagLength(),
          key,
          Buffers.toArray(input.iv()),
          Buffers.toArray(input.cipherTxt()),
          Buffers.toArray(input.authTag()),
          Buffers.toArray(input.aad())
        )
      );
    } catch (GeneralSecurityException e) {
      throw opaque(e);
    } finally {
      Bytes.zero(key);
    }
  }

  private static DigestAlgorithm alg(software.amazon.cryptography.primitives.model.DigestAlgorithm algorithm) {
    return DigestAlgorithm.valueOf(algorithm.name());
  }

  private static boolean validHkdfLength(DigestAlgorithm algorithm, int length) {
    return 1 <= length && length <= 255 * Digests.length(algorithm);
  }

  // A salt that is present but empty is rejected; an absent salt means HashLen zero bytes.
  private static boolean isEmpty(ByteBuffer optional) {
    return optional != null && optional.limit() == 0;
  }

  private static byte[] toArrayOrNull(ByteBuffer optional) {
    return optional == null ? null : Buffers.toArray(optional);
  }

  private static AwsCryptographicPrimitivesError error(String message) {
    return AwsCryptographicPrimitivesError.builder().message(message).build();
  }

  // OpaqueError.build() also makes a Throwable obj the cause, so the message is the JCE exception's.
  private static OpaqueError opaque(GeneralSecurityException e) {
    return OpaqueError.builder().obj(e).build();
  }

  public interface Builder {
    Builder CryptoConfig(CryptoConfig CryptoConfig);

    CryptoConfig CryptoConfig();

    AtomicPrimitives build();
  }

  static class BuilderImpl implements Builder {

    protected CryptoConfig CryptoConfig;

    protected BuilderImpl() {}

    public Builder CryptoConfig(CryptoConfig CryptoConfig) {
      this.CryptoConfig = CryptoConfig;
      return this;
    }

    public CryptoConfig CryptoConfig() {
      return this.CryptoConfig;
    }

    public AtomicPrimitives build() {
      if (Objects.isNull(this.CryptoConfig())) {
        throw new IllegalArgumentException(
          "Missing value for required field `CryptoConfig`"
        );
      }
      return new AtomicPrimitives(this);
    }
  }
}
