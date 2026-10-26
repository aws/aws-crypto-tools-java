// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.primitives;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Objects;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.exceptions.MaterialProvidersException;
import software.amazon.cryptography.materialproviders.internal.primitives.Ecdh;
import software.amazon.cryptography.materialproviders.internal.primitives.Ecdsa;
import software.amazon.cryptography.materialproviders.internal.primitives.Rsa;
import software.amazon.cryptography.materialproviders.internal.primitives.RsaKeyGeneration;
import software.amazon.cryptography.materialproviders.keyrings.EcdhCurveSpec;
import software.amazon.cryptography.materialproviders.keyrings.PaddingScheme;
import software.amazon.cryptography.oldapi.primitives.model.CompressPublicKeyInput;
import software.amazon.cryptography.oldapi.primitives.model.CompressPublicKeyOutput;
import software.amazon.cryptography.oldapi.primitives.model.DecompressPublicKeyInput;
import software.amazon.cryptography.oldapi.primitives.model.DecompressPublicKeyOutput;
import software.amazon.cryptography.oldapi.primitives.model.DeriveSharedSecretInput;
import software.amazon.cryptography.oldapi.primitives.model.DeriveSharedSecretOutput;
import software.amazon.cryptography.oldapi.primitives.model.ECCPrivateKey;
import software.amazon.cryptography.oldapi.primitives.model.ECCPublicKey;
import software.amazon.cryptography.oldapi.primitives.model.ECDHCurveSpec;
import software.amazon.cryptography.oldapi.primitives.model.ECDSASignInput;
import software.amazon.cryptography.oldapi.primitives.model.ECDSASignatureAlgorithm;
import software.amazon.cryptography.oldapi.primitives.model.ECDSAVerifyInput;
import software.amazon.cryptography.oldapi.primitives.model.GenerateECCKeyPairInput;
import software.amazon.cryptography.oldapi.primitives.model.GenerateECCKeyPairOutput;
import software.amazon.cryptography.oldapi.primitives.model.GenerateECDSASignatureKeyInput;
import software.amazon.cryptography.oldapi.primitives.model.GenerateECDSASignatureKeyOutput;
import software.amazon.cryptography.oldapi.primitives.model.GenerateRSAKeyPairInput;
import software.amazon.cryptography.oldapi.primitives.model.GenerateRSAKeyPairOutput;
import software.amazon.cryptography.oldapi.primitives.model.GetPublicKeyFromPrivateKeyInput;
import software.amazon.cryptography.oldapi.primitives.model.GetPublicKeyFromPrivateKeyOutput;
import software.amazon.cryptography.oldapi.primitives.model.GetRSAKeyModulusLengthInput;
import software.amazon.cryptography.oldapi.primitives.model.GetRSAKeyModulusLengthOutput;
import software.amazon.cryptography.oldapi.primitives.model.ParsePublicKeyInput;
import software.amazon.cryptography.oldapi.primitives.model.ParsePublicKeyOutput;
import software.amazon.cryptography.oldapi.primitives.model.RSADecryptInput;
import software.amazon.cryptography.oldapi.primitives.model.RSAEncryptInput;
import software.amazon.cryptography.oldapi.primitives.model.RSAPaddingMode;
import software.amazon.cryptography.oldapi.primitives.model.RSAPrivateKey;
import software.amazon.cryptography.oldapi.primitives.model.RSAPublicKey;
import software.amazon.cryptography.oldapi.primitives.model.ValidatePublicKeyInput;
import software.amazon.cryptography.oldapi.primitives.model.ValidatePublicKeyOutput;
import software.amazon.cryptography.materialproviders.internal.primitives.AesGcm;
import software.amazon.cryptography.oldapi.materialproviders.internal.Buffers;
import software.amazon.cryptography.materialproviders.internal.primitives.Bytes;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.internal.primitives.EcKeys;
import software.amazon.cryptography.materialproviders.internal.primitives.Digests;
import software.amazon.cryptography.materialproviders.internal.primitives.Hkdf;
import software.amazon.cryptography.materialproviders.internal.primitives.KdfCounterMode;
import software.amazon.cryptography.materialproviders.internal.primitives.Randoms;
import software.amazon.cryptography.oldapi.primitives.model.AESDecryptInput;
import software.amazon.cryptography.oldapi.primitives.model.AESEncryptInput;
import software.amazon.cryptography.oldapi.primitives.model.AESEncryptOutput;
import software.amazon.cryptography.oldapi.primitives.model.AesKdfCtrInput;
import software.amazon.cryptography.oldapi.primitives.model.AwsCryptographicPrimitivesError;
import software.amazon.cryptography.oldapi.primitives.model.CryptoConfig;
import software.amazon.cryptography.materialproviders.internal.primitives.DigestAlgorithm;
import software.amazon.cryptography.oldapi.primitives.model.DigestInput;
import software.amazon.cryptography.oldapi.primitives.model.GenerateRandomBytesInput;
import software.amazon.cryptography.oldapi.primitives.model.HMacInput;
import software.amazon.cryptography.oldapi.primitives.model.HkdfExpandInput;
import software.amazon.cryptography.oldapi.primitives.model.HkdfExtractInput;
import software.amazon.cryptography.oldapi.primitives.model.HkdfInput;
import software.amazon.cryptography.oldapi.primitives.model.KdfCtrInput;
import software.amazon.cryptography.oldapi.primitives.model.OpaqueError;

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

  // The Dafny-based MPL threw a plain RuntimeException when key generation failed.
  public GenerateRSAKeyPairOutput GenerateRSAKeyPair(GenerateRSAKeyPairInput input) {
    byte[][] pems;
    try {
      pems = RsaKeyGeneration.generateKeyPair(input.lengthBits());
    } catch (MaterialProvidersException e) {
      throw new RuntimeException(e.getMessage());
    }
    return GenerateRSAKeyPairOutput
      .builder()
      .publicKey(RSAPublicKey.builder().lengthBits(input.lengthBits()).pem(ByteBuffer.wrap(pems[0])).build())
      .privateKey(RSAPrivateKey.builder().lengthBits(input.lengthBits()).pem(ByteBuffer.wrap(pems[1])).build())
      .build();
  }

  public GetRSAKeyModulusLengthOutput GetRSAKeyModulusLength(GetRSAKeyModulusLengthInput input) {
    try {
      return GetRSAKeyModulusLengthOutput.builder().length(Rsa.modulusLengthBits(Buffers.toArray(input.publicKey()))).build();
    } catch (MaterialProvidersException e) {
      throw rsaOrEcdsaError(e);
    }
  }

  public ByteBuffer RSAEncrypt(RSAEncryptInput input) {
    byte[] plaintext = Buffers.toArray(input.plaintext());
    try {
      return ByteBuffer.wrap(Rsa.encrypt(padding(input.padding()), Buffers.toArray(input.publicKey()), plaintext));
    } catch (MaterialProvidersException e) {
      throw rsaOrEcdsaError(e);
    } finally {
      Bytes.zero(plaintext);
    }
  }

  public ByteBuffer RSADecrypt(RSADecryptInput input) {
    byte[] privateKey = Buffers.toArray(input.privateKey());
    try {
      return ByteBuffer.wrap(Rsa.decrypt(padding(input.padding()), privateKey, Buffers.toArray(input.cipherText())));
    } catch (MaterialProvidersException e) {
      throw rsaOrEcdsaError(e);
    } finally {
      Bytes.zero(privateKey);
    }
  }

  public GenerateECDSASignatureKeyOutput GenerateECDSASignatureKey(GenerateECDSASignatureKeyInput input) {
    byte[][] keys;
    try {
      keys = Ecdsa.generateKeyPair(signature(input.signatureAlgorithm()));
    } catch (MaterialProvidersException e) {
      throw rsaOrEcdsaError(e);
    }
    return GenerateECDSASignatureKeyOutput
      .builder()
      .signatureAlgorithm(input.signatureAlgorithm())
      .verificationKey(ByteBuffer.wrap(keys[0]))
      .signingKey(ByteBuffer.wrap(keys[1]))
      .build();
  }

  public ByteBuffer ECDSASign(ECDSASignInput input) {
    byte[] signingKey = Buffers.toArray(input.signingKey());
    try {
      return ByteBuffer.wrap(Ecdsa.sign(signature(input.signatureAlgorithm()), signingKey, Buffers.toArray(input.message())));
    } catch (ValidationException e) {
      if (EcKeys.EMPTY_SIGNING_KEY.equals(e.getMessage())) {
        // The Dafny-based MPL passed the empty key to BigInteger, which throws this.
        throw new NumberFormatException("Zero length BigInteger");
      }
      throw rsaOrEcdsaError(e);
    } catch (MaterialProvidersException e) {
      throw rsaOrEcdsaError(e);
    } finally {
      Bytes.zero(signingKey);
    }
  }

  public Boolean ECDSAVerify(ECDSAVerifyInput input) {
    try {
      return Ecdsa.verify(
        signature(input.signatureAlgorithm()),
        Buffers.toArray(input.verificationKey()),
        Buffers.toArray(input.message()),
        Buffers.toArray(input.signature())
      );
    } catch (ValidationException e) {
      if (EcKeys.EMPTY_VERIFICATION_KEY.equals(e.getMessage())) {
        // The Dafny-based MPL copied bytes [1, 0) of the empty key, which throws this.
        throw new IllegalArgumentException("1 > 0");
      }
      throw rsaOrEcdsaError(e);
    } catch (MaterialProvidersException e) {
      throw rsaOrEcdsaError(e);
    }
  }

  public GenerateECCKeyPairOutput GenerateECCKeyPair(GenerateECCKeyPairInput input) {
    byte[][] keys = Ecdh.generateKeyPair(curve(input.eccCurve()));
    return GenerateECCKeyPairOutput
      .builder()
      .eccCurve(input.eccCurve())
      .privateKey(ECCPrivateKey.builder().pem(ByteBuffer.wrap(keys[0])).build())
      .publicKey(ECCPublicKey.builder().der(ByteBuffer.wrap(keys[1])).build())
      .build();
  }

  public GetPublicKeyFromPrivateKeyOutput GetPublicKeyFromPrivateKey(GetPublicKeyFromPrivateKeyInput input) {
    byte[] privateKey = Buffers.toArray(input.privateKey().pem());
    try {
      byte[] publicKey = Ecdh.publicKeyFromPrivateKey(curve(input.eccCurve()), privateKey);
      return GetPublicKeyFromPrivateKeyOutput
        .builder()
        .eccCurve(input.eccCurve())
        .privateKey(ECCPrivateKey.builder().pem(ByteBuffer.wrap(Buffers.toArray(input.privateKey().pem()))).build())
        .publicKey(ByteBuffer.wrap(publicKey))
        .build();
    } catch (MaterialProvidersException e) {
      throw ecdhError(e);
    } finally {
      Bytes.zero(privateKey);
    }
  }

  public ValidatePublicKeyOutput ValidatePublicKey(ValidatePublicKeyInput input) {
    try {
      boolean valid = Ecdh.validatePublicKey(curve(input.eccCurve()), Buffers.toArray(input.publicKey()));
      return ValidatePublicKeyOutput.builder().success(valid).build();
    } catch (MaterialProvidersException e) {
      throw ecdhError(e);
    }
  }

  public DeriveSharedSecretOutput DeriveSharedSecret(DeriveSharedSecretInput input) {
    byte[] privateKey = Buffers.toArray(input.privateKey().pem());
    try {
      byte[] secret = Ecdh.deriveSharedSecret(curve(input.eccCurve()), privateKey, Buffers.toArray(input.publicKey().der()));
      return DeriveSharedSecretOutput.builder().sharedSecret(ByteBuffer.wrap(secret)).build();
    } catch (MaterialProvidersException e) {
      throw ecdhError(e);
    } finally {
      Bytes.zero(privateKey);
    }
  }

  // The Dafny-based MPL ignored eccCurve here.
  public CompressPublicKeyOutput CompressPublicKey(CompressPublicKeyInput input) {
    try {
      byte[] compressed = Ecdh.compressPublicKey(Buffers.toArray(input.publicKey().der()));
      return CompressPublicKeyOutput.builder().compressedPublicKey(ByteBuffer.wrap(compressed)).build();
    } catch (MaterialProvidersException e) {
      throw ecdhError(e);
    }
  }

  public DecompressPublicKeyOutput DecompressPublicKey(DecompressPublicKeyInput input) {
    try {
      byte[] der = Ecdh.decompressPublicKey(Buffers.toArray(input.compressedPublicKey()), curve(input.eccCurve()));
      return DecompressPublicKeyOutput.builder().publicKey(ECCPublicKey.builder().der(ByteBuffer.wrap(der)).build()).build();
    } catch (MaterialProvidersException e) {
      throw ecdhError(e);
    }
  }

  public ParsePublicKeyOutput ParsePublicKey(ParsePublicKeyInput input) {
    try {
      byte[] der = Ecdh.parsePublicKey(Buffers.toArray(input.publicKey()));
      return ParsePublicKeyOutput.builder().publicKey(ECCPublicKey.builder().der(ByteBuffer.wrap(der)).build()).build();
    } catch (MaterialProvidersException e) {
      throw ecdhError(e);
    }
  }

  private static PaddingScheme padding(RSAPaddingMode padding) {
    switch (padding) {
      case PKCS1:
        return PaddingScheme.PKCS1;
      case OAEP_SHA1:
        return PaddingScheme.OAEP_SHA1_MGF1;
      case OAEP_SHA256:
        return PaddingScheme.OAEP_SHA256_MGF1;
      case OAEP_SHA384:
        return PaddingScheme.OAEP_SHA384_MGF1;
      case OAEP_SHA512:
        return PaddingScheme.OAEP_SHA512_MGF1;
      default:
        throw new IllegalArgumentException("unknown RSA padding " + padding);
    }
  }

  private static AlgorithmSuite.Signature signature(ECDSASignatureAlgorithm algorithm) {
    return AlgorithmSuite.Signature.valueOf(algorithm.name());
  }

  private static EcdhCurveSpec curve(ECDHCurveSpec curve) {
    return EcdhCurveSpec.valueOf(curve.name());
  }

  // RSA and ECDSA returned a JCE or BouncyCastle exception as OpaqueError, and their own checks as
  // AwsCryptographicPrimitivesError. The core reports the former with the exception's own message and the exception as cause.
  public static RuntimeException rsaOrEcdsaError(MaterialProvidersException e) {
    Throwable cause = e.getCause();
    if (cause != null && Objects.equals(e.getMessage(), cause.getMessage())) {
      return OpaqueError.builder().obj(cause).build();
    }
    return error(e.getMessage());
  }

  // ECDH returned every failure as AwsCryptographicPrimitivesError with the underlying message, except unsupported SM2.
  // A null message makes the error's builder throw IllegalArgumentException, which the Dafny-based MPL threw too.
  public static RuntimeException ecdhError(MaterialProvidersException e) {
    if (Ecdh.SM2_UNSUPPORTED.equals(e.getMessage())) {
      return OpaqueError.builder().obj(new RuntimeException(e.getMessage())).build();
    }
    return error(e.getMessage());
  }

  private static DigestAlgorithm alg(software.amazon.cryptography.oldapi.primitives.model.DigestAlgorithm algorithm) {
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
