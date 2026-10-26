// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.primitives;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.keyrings.EcdhCurveSpec;

/**
 * ECDH key generation, key agreement, and public key encodings.
 * Private keys are PEM PKCS #8 ("PRIVATE KEY"); public keys are DER X.509 SubjectPublicKeyInfo,
 * or a SEC 1 compressed point where named.
 *
 * <p>BouncyCastle does the work through a provider instance this class holds; it is never registered
 * with {@link java.security.Security}. Private PEM keys are parsed, and compressed points decompressed,
 * by the default JCA providers instead, as the Dafny-based MPL did.
 *
 * <p>Every failure is a {@link ValidationException} carrying the underlying exception's message (which may be null)
 * and that exception as the cause; the library's own checks have no cause.
 * SM2 is supported by {@link #generateKeyPair} only.
 */
public final class Ecdh {

  public static final String SM2_UNSUPPORTED = "SM2 Not yet Supported.";

  private static final Provider BOUNCY_CASTLE = new BouncyCastleProvider();

  private Ecdh() {}

  /**
   * Returns {privateKey, publicKey}: a PEM private key and a DER public key.
   * For SM2 they are instead the private scalar as {@link BigInteger#toByteArray()} and the uncompressed point.
   */
  public static byte[][] generateKeyPair(EcdhCurveSpec curve) {
    if (curve == EcdhCurveSpec.SM2) {
      return generateSm2KeyPair();
    }
    KeyPair pair;
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BOUNCY_CASTLE);
      generator.initialize(new ECGenParameterSpec(curveName(curve)), Randoms.secureRandom());
      pair = generator.generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("EC key generation unavailable for " + curve, e);
    }
    byte[] privateKeyInfo = pair.getPrivate().getEncoded();
    try {
      return new byte[][] { Pem.encode("PRIVATE KEY", privateKeyInfo), pair.getPublic().getEncoded() };
    } finally {
      Bytes.zero(privateKeyInfo);
    }
  }

  /** The DER public key of a PEM private key, which must be on {@code curve}. */
  public static byte[] publicKeyFromPrivateKey(EcdhCurveSpec curve, byte[] privateKeyPem) {
    requireNotSm2(curve);
    ECPrivateKey privateKey;
    ECParameterSpec spec;
    try {
      privateKey = (ECPrivateKey) parsePrivateKey(privateKeyPem);
      spec = ECNamedCurveTable.getParameterSpec(curveName(curve));
    } catch (Exception e) {
      throw failure(e);
    }
    // Comparing the group orders tells the curves apart: P-256, P-384, and P-521 have different orders.
    if (privateKey.getParams().getOrder().compareTo(spec.getG().getCurve().getOrder()) != 0) {
      throw new ValidationException("Private Key NOT on configured curve spec.");
    }
    try {
      ECPoint q = spec.getG().multiply(privateKey.getS());
      return KeyFactory.getInstance("EC", BOUNCY_CASTLE).generatePublic(new ECPublicKeySpec(q, spec)).getEncoded();
    } catch (Exception e) {
      throw failure(e);
    }
  }

  /**
   * NIST SP 800-56A rev. 3 section 5.6.2.3.3 (ECC full public-key validation) of a DER public key on {@code curve}.
   *
   * @return false only for a point on the curve with x = 0
   * @throws ValidationException if the key does not parse or its point is not on {@code curve}
   */
  public static boolean validatePublicKey(EcdhCurveSpec curve, byte[] publicKeyDer) {
    requireNotSm2(curve);
    try {
      org.bouncycastle.jce.interfaces.ECPublicKey key = (org.bouncycastle.jce.interfaces.ECPublicKey) parsePublicKeyDer(publicKeyDer);
      ECCurve ecCurve = ECNamedCurveTable.getParameterSpec(curveName(curve)).getCurve();
      BigInteger x = key.getQ().getAffineXCoord().toBigInteger();
      ecCurve.validatePoint(x, key.getQ().getAffineYCoord().toBigInteger());
      // The key factory accepts only a finite point with coordinates in [0, p), and validatePoint only one on this curve;
      // these curves have prime order, so no point has y = 0. Of the routine's checks, only x > 0 is left.
      return x.signum() > 0;
    } catch (Exception e) {
      throw failure(e);
    }
  }

  /**
   * The ECDH shared secret: the x coordinate of the product, field-length big-endian.
   * {@code curve} only excludes SM2; the keys' own curves are used, and the public key is not validated here.
   */
  public static byte[] deriveSharedSecret(EcdhCurveSpec curve, byte[] privateKeyPem, byte[] publicKeyDer) {
    requireNotSm2(curve);
    try {
      KeyAgreement agreement = KeyAgreement.getInstance("ECDH", BOUNCY_CASTLE);
      agreement.init(parsePrivateKey(privateKeyPem), Randoms.secureRandom());
      agreement.doPhase(parsePublicKeyDer(publicKeyDer), true);
      return agreement.generateSecret();
    } catch (Exception e) {
      throw failure(e);
    }
  }

  /** The SEC 1 compressed point of a DER public key, on whatever curve the key names. */
  public static byte[] compressPublicKey(byte[] publicKeyDer) {
    try {
      return ((org.bouncycastle.jce.interfaces.ECPublicKey) parsePublicKeyDer(publicKeyDer)).getQ().getEncoded(true);
    } catch (Exception e) {
      throw failure(e);
    }
  }

  /** The DER public key of a compressed point on {@code curve}; decoded as {@link EcKeys#publicKey} decodes. */
  public static byte[] decompressPublicKey(byte[] compressed, EcdhCurveSpec curve) {
    try {
      java.security.spec.ECParameterSpec spec = EcKeys.parameters(curveName(curve));
      java.security.spec.ECPoint point = EcKeys.decodePoint(compressed, spec);
      return KeyFactory.getInstance("EC").generatePublic(new java.security.spec.ECPublicKeySpec(point, spec)).getEncoded();
    } catch (Exception e) {
      throw failure(e);
    }
  }

  /** The DER public key, re-encoded, if it parses as an X.509 SubjectPublicKeyInfo EC key. */
  public static byte[] parsePublicKey(byte[] publicKeyDer) {
    try {
      byte[] reencoded = SubjectPublicKeyInfo.getInstance(publicKeyDer).getEncoded();
      return parsePublicKeyDer(reencoded).getEncoded();
    } catch (Exception e) {
      throw failure(e);
    }
  }

  private static byte[][] generateSm2KeyPair() {
    X9ECParameters sm2 = GMNamedCurves.getByName("sm2p256v1");
    ECKeyPairGenerator generator = new ECKeyPairGenerator();
    generator.init(
      new ECKeyGenerationParameters(new ECDomainParameters(sm2.getCurve(), sm2.getG(), sm2.getN(), sm2.getH()), Randoms.secureRandom())
    );
    AsymmetricCipherKeyPair pair = generator.generateKeyPair();
    return new byte[][] {
      ((ECPrivateKeyParameters) pair.getPrivate()).getD().toByteArray(),
      ((ECPublicKeyParameters) pair.getPublic()).getQ().getEncoded(false),
    };
  }

  private static PrivateKey parsePrivateKey(byte[] pem) throws Exception {
    byte[] der = Pem.content(pem);
    try {
      return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
    } finally {
      Bytes.zero(der);
    }
  }

  private static PublicKey parsePublicKeyDer(byte[] der) throws GeneralSecurityException {
    return KeyFactory.getInstance("EC", BOUNCY_CASTLE).generatePublic(new X509EncodedKeySpec(der));
  }

  private static void requireNotSm2(EcdhCurveSpec curve) {
    if (curve == EcdhCurveSpec.SM2) {
      throw new ValidationException(SM2_UNSUPPORTED);
    }
  }

  private static ValidationException failure(Exception e) {
    return new ValidationException(e.getMessage(), e);
  }

  private static String curveName(EcdhCurveSpec curve) {
    switch (curve) {
      case ECC_NIST_P256:
        return "secp256r1";
      case ECC_NIST_P384:
        return "secp384r1";
      case ECC_NIST_P521:
        return "secp521r1";
      case SM2:
        return "SM2";
      default:
        throw new IllegalArgumentException("unknown ECDH curve " + curve);
    }
  }
}
