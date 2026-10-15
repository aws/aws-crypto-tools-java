// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal.primitives;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import software.amazon.cryptography.mpl.AlgorithmSuite;
import software.amazon.cryptography.mpl.exceptions.CryptographicException;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

/**
 * The encodings the message format and the materials use for ECDSA keys, and their JCA keys:
 * the private key as {@link BigInteger#toByteArray()} of the scalar (big-endian two's complement),
 * the public key as a SEC 1 compressed point.
 * Keys are built by the installed JCA providers; a missing EC provider is a {@link CryptographicException}.
 */
public final class EcKeys {

  public static final String EMPTY_SIGNING_KEY = "ECDSA signing key is empty.";
  public static final String EMPTY_VERIFICATION_KEY = "ECDSA verification key is empty.";

  private static final BigInteger TWO = BigInteger.valueOf(2);
  private static final BigInteger THREE = BigInteger.valueOf(3);
  private static final BigInteger FOUR = BigInteger.valueOf(4);

  private EcKeys() {}

  /** @throws CryptographicException if no installed provider has the curve */
  public static ECParameterSpec parameters(AlgorithmSuite.Signature signature) {
    try {
      return parameters(signature.curveName());
    } catch (GeneralSecurityException e) {
      throw new CryptographicException(e.getMessage(), e);
    }
  }

  /** The default provider's parameters for a curve such as "secp256r1". */
  static ECParameterSpec parameters(String curveName) throws GeneralSecurityException {
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec(curveName));
    return parameters.getParameterSpec(ECParameterSpec.class);
  }

  /** {@link BigInteger#toByteArray()} of the private scalar, so it may carry a leading zero byte. */
  public static byte[] encodePrivateKey(ECPrivateKey key) {
    return key.getS().toByteArray();
  }

  /**
   * The private key whose scalar is {@code encoded} read as two's complement.
   *
   * @throws ValidationException if {@code encoded} is empty or the key factory rejects the scalar
   */
  public static PrivateKey privateKey(AlgorithmSuite.Signature signature, byte[] encoded) {
    ECParameterSpec parameters = parameters(signature);
    if (encoded.length == 0) {
      throw new ValidationException(EMPTY_SIGNING_KEY);
    }
    ECPrivateKeySpec spec = new ECPrivateKeySpec(new BigInteger(encoded), parameters);
    try {
      return KeyFactory.getInstance("EC").generatePrivate(spec);
    } catch (GeneralSecurityException e) {
      throw new ValidationException(e.getMessage(), e);
    }
  }

  /** The compressed point: 0x02 for even y or 0x03 for odd y, then x as a field-length big-endian integer. */
  public static byte[] compressPublicKey(AlgorithmSuite.Signature signature, ECPublicKey key) {
    ECPoint point = key.getW();
    int fieldLength = signature == AlgorithmSuite.Signature.ECDSA_P256 ? 32 : 48;
    byte[] compressed = new byte[fieldLength + 1];
    compressed[0] = point.getAffineY().testBit(0) ? (byte) 3 : (byte) 2;
    byte[] x = point.getAffineX().toByteArray();
    int significant = Math.min(x.length, fieldLength);
    System.arraycopy(x, x.length - significant, compressed, compressed.length - significant, significant);
    return compressed;
  }

  /**
   * The public key from a compressed point.
   * x is every byte after the first, read unsigned, so a point of any length is decoded;
   * x is not reduced modulo p.
   *
   * @throws ValidationException if {@code compressed} is empty, the first byte is not 2 or 3, x has no point on the curve,
   *   or the key factory rejects the point
   */
  public static PublicKey publicKey(AlgorithmSuite.Signature signature, byte[] compressed) {
    ECParameterSpec spec = parameters(signature);
    if (compressed.length == 0) {
      throw new ValidationException(EMPTY_VERIFICATION_KEY);
    }
    ECPoint point;
    try {
      point = decodePoint(compressed, spec);
    } catch (ValidationException e) {
      throw new ValidationException("Could not decode Elliptic Curve point due to: " + e.getMessage() + ".", e);
    }
    try {
      return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
    } catch (GeneralSecurityException e) {
      throw new ValidationException(e.getMessage(), e);
    }
  }

  /**
   * Decodes a compressed point as SEC 1 v2 section 2.3.4 does, for a curve with p = 3 mod 4
   * (P-256, P-384, and P-521 all have it).
   *
   * @throws IllegalArgumentException if {@code compressed} is empty
   * @throws ValidationException with the reason, if the first byte is not 2 or 3 or x has no point on the curve
   */
  static ECPoint decodePoint(byte[] compressed, ECParameterSpec spec) {
    BigInteger x = new BigInteger(1, Arrays.copyOfRange(compressed, 1, compressed.length));
    boolean oddY;
    if (compressed[0] == 2) {
      oddY = false;
    } else if (compressed[0] == 3) {
      oddY = true;
    } else {
      throw new ValidationException("Compressed y value was invalid");
    }
    BigInteger p = ((ECFieldFp) spec.getCurve().getField()).getP();
    BigInteger alpha = x
      .modPow(THREE, p)
      .add(spec.getCurve().getA().multiply(x))
      .add(spec.getCurve().getB())
      .mod(p);
    BigInteger beta = alpha.modPow(p.add(BigInteger.ONE).divide(FOUR), p);
    BigInteger y = beta.testBit(0) == oddY ? beta : p.subtract(beta);
    // For an x with no point on the curve, beta is not a square root of alpha; accepting it would allow invalid-curve attacks.
    if (!alpha.equals(y.modPow(TWO, p))) {
      throw new ValidationException("Y was invalid");
    }
    return new ECPoint(x, y);
  }
}
