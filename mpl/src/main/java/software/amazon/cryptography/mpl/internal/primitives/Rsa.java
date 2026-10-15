// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal.primitives;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import software.amazon.cryptography.mpl.exceptions.CryptographicException;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.keyrings.PaddingScheme;

/**
 * RSA encryption with BouncyCastle's lightweight API, on PEM keys:
 * public keys as X.509 SubjectPublicKeyInfo ("PUBLIC KEY"), private keys as PKCS #8 ("PRIVATE KEY").
 *
 * <p>A failure inside BouncyCastle, including a malformed key, is reported with BouncyCastle's message
 * and its exception as the cause. The library's own checks have no cause.
 */
public final class Rsa {

  private static final int MIN_LENGTH_BITS = 81;

  private Rsa() {}

  /**
   * The bit length of the public key's modulus.
   *
   * @throws ValidationException if the key does not parse, or the modulus is shorter than 81 bits
   */
  public static int modulusLengthBits(byte[] publicKeyPem) {
    int length = parsePublicKey(publicKeyPem).getModulus().bitLength();
    if (length < MIN_LENGTH_BITS) {
      throw new ValidationException("Unsupported length for RSA modulus.");
    }
    return length;
  }

  /** @throws ValidationException if the key or plaintext is empty, the key does not parse, or the plaintext is too long */
  public static byte[] encrypt(PaddingScheme padding, byte[] publicKeyPem, byte[] plaintext) {
    if (publicKeyPem.length == 0 || plaintext.length == 0) {
      throw new ValidationException("");
    }
    RSAKeyParameters key = parsePublicKey(publicKeyPem);
    try {
      AsymmetricBlockCipher cipher = cipher(padding);
      cipher.init(true, key);
      return cipher.processBlock(plaintext, 0, plaintext.length);
    } catch (Exception e) {
      throw new ValidationException(e.getMessage(), e);
    }
  }

  /**
   * @throws ValidationException if the key or ciphertext is empty, or the key does not parse
   * @throws CryptographicException if the ciphertext does not decrypt under the key and padding
   */
  public static byte[] decrypt(PaddingScheme padding, byte[] privateKeyPem, byte[] ciphertext) {
    if (privateKeyPem.length == 0 || ciphertext.length == 0) {
      throw new ValidationException("");
    }
    RSAKeyParameters key = parsePrivateKey(privateKeyPem);
    try {
      AsymmetricBlockCipher cipher = cipher(padding);
      cipher.init(false, key);
      return cipher.processBlock(ciphertext, 0, ciphertext.length);
    } catch (Exception e) {
      throw new CryptographicException(e.getMessage(), e);
    }
  }

  //= spec/framework/raw-rsa-keyring.md#public-key
  //# The raw RSA keyring SHOULD support loading PEM
  //# encoded [X.509 SubjectPublicKeyInfo structures]
  //# (https://tools.ietf.org/html/rfc5280#section-4.1) as public keys.
  //= spec/framework/raw-rsa-keyring.md#public-key
  //= type=implication
  //# The public key MUST follow the [RSA specification for public keys](#rsa)
  private static RSAKeyParameters parsePublicKey(byte[] pem) {
    try {
      return (RSAKeyParameters) PublicKeyFactory.createKey(Pem.content(pem));
    } catch (Exception e) {
      throw new ValidationException(e.getMessage(), e);
    }
  }

  //= spec/framework/raw-rsa-keyring.md#private-key
  //= type=implication
  //# The private key MUST follow the [RSA specification for private keys](#rsa)
  //= spec/framework/raw-rsa-keyring.md#private-key
  //= type=implication
  //# The
  //# private key SHOULD contain all Chinese Remainder Theorem (CRT)
  //# components (public exponent, prime factors, CRT exponents, and CRT
  //# coefficient).
  private static RSAKeyParameters parsePrivateKey(byte[] pem) {
    byte[] der = null;
    try {
      der = Pem.content(pem);
      return (RSAKeyParameters) PrivateKeyFactory.createKey(der);
    } catch (Exception e) {
      throw new ValidationException(e.getMessage(), e);
    } finally {
      Bytes.zero(der);
    }
  }

  // OAEP uses the same digest for MGF1 as for the label hash.
  private static AsymmetricBlockCipher cipher(PaddingScheme padding) {
    switch (padding) {
      case PKCS1:
        return new PKCS1Encoding(new RSABlindedEngine());
      case OAEP_SHA1_MGF1:
        return new OAEPEncoding(new RSABlindedEngine(), new SHA1Digest());
      case OAEP_SHA256_MGF1:
        return new OAEPEncoding(new RSABlindedEngine(), new SHA256Digest());
      case OAEP_SHA384_MGF1:
        return new OAEPEncoding(new RSABlindedEngine(), new SHA384Digest());
      case OAEP_SHA512_MGF1:
        return new OAEPEncoding(new RSABlindedEngine(), new SHA512Digest());
      default:
        throw new IllegalArgumentException("unknown RSA padding " + padding);
    }
  }
}
