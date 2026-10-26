// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.primitives;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.exceptions.CryptographicException;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

/**
 * ECDSA over SHA-256 (P-256) or SHA-384 (P-384) with the installed JCA providers ("NONEwithECDSA" on the digest).
 * Without a provider for EC keys or that signature, operations throw {@link CryptographicException}.
 * Keys use the {@link EcKeys} encodings; signatures are DER, always 71 bytes for P-256 and 103 for P-384.
 *
 * <p>A failure inside the provider is reported with the provider's message and its exception as the cause;
 * the library's own messages differ from their cause's.
 */
public final class Ecdsa {

  private static final String RAW_SIGNATURE = "NONEwithECDSA";

  private Ecdsa() {}

  /** Returns {verificationKey, signingKey}. */
  public static byte[][] generateKeyPair(AlgorithmSuite.Signature algorithm) {
    KeyPair pair;
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(new ECGenParameterSpec(algorithm.curveName()), Randoms.secureRandom());
      pair = generator.generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new CryptographicException(e.getMessage(), e);
    }
    return new byte[][] {
      EcKeys.compressPublicKey(algorithm, (ECPublicKey) pair.getPublic()),
      EcKeys.encodePrivateKey((ECPrivateKey) pair.getPrivate()),
    };
  }

  /**
   * @throws ValidationException if {@code signingKey} is empty or the provider rejects the key
   * @throws CryptographicException if signing fails
   */
  public static byte[] sign(AlgorithmSuite.Signature algorithm, byte[] signingKey, byte[] message) {
    Signature signer = rawSignature();
    ECPrivateKey key = (ECPrivateKey) EcKeys.privateKey(algorithm, signingKey);
    byte[] digest = Digests.digest(digestAlgorithm(algorithm), message);
    try {
      signer.initSign(key, Randoms.secureRandom());
    } catch (InvalidKeyException e) {
      throw new ValidationException(
        String.format("Signature Cipher does not support provided key.Signature %sKey %s", signer, key),
        e
      );
    }
    try {
      return fixedLengthSignature(signer, digest, key, signatureLength(algorithm));
    } catch (SignatureException e) {
      throw new CryptographicException(e.getMessage(), e);
    }
  }

  /**
   * Whether {@code signature} is a valid signature of {@code message}.
   *
   * @throws ValidationException if the key is empty or does not decode, or the provider cannot parse the signature
   */
  public static boolean verify(AlgorithmSuite.Signature algorithm, byte[] verificationKey, byte[] message, byte[] signature) {
    PublicKey key = EcKeys.publicKey(algorithm, verificationKey);
    Signature verifier = rawSignature();
    try {
      verifier.initVerify(key);
    } catch (InvalidKeyException e) {
      throw new ValidationException(
        String.format("Signature does not support provided key.Signature %sKey %s", verifier, key),
        e
      );
    }
    try {
      verifier.update(Digests.digest(digestAlgorithm(algorithm), message));
    } catch (SignatureException e) {
      throw new IllegalStateException("update after initVerify failed", e);
    }
    try {
      return verifier.verify(signature);
    } catch (SignatureException e) {
      throw new ValidationException(
        String.format("Signature Cipher does not support provided key.Signature %sKey %s", verifier, key),
        e
      );
    }
  }

  /**
   * A DER signature of exactly {@code length} bytes; the ESDK needs a fixed-length footer.
   * A DER signature's length varies with r and s. Replacing s with n - s gives another valid signature,
   * which usually has the length; otherwise sign again.
   */
  static byte[] fixedLengthSignature(Signature signer, byte[] digest, ECPrivateKey key, int length)
    throws SignatureException {
    byte[] signature;
    do {
      signer.update(digest);
      signature = signer.sign();
      if (signature.length != length) {
        ASN1Sequence sequence = ASN1Sequence.getInstance(signature);
        ASN1Integer r = (ASN1Integer) sequence.getObjectAt(0);
        ASN1Integer s = (ASN1Integer) sequence.getObjectAt(1);
        ASN1Integer negated = new ASN1Integer(key.getParams().getOrder().subtract(s.getPositiveValue()));
        try {
          signature = new DERSequence(new ASN1Encodable[] { r, negated }).getEncoded();
        } catch (IOException e) {
          throw new SignatureException(e);
        }
      }
    } while (signature.length != length);
    return signature;
  }

  private static Signature rawSignature() {
    try {
      return Signature.getInstance(RAW_SIGNATURE);
    } catch (NoSuchAlgorithmException e) {
      throw new CryptographicException("Requested Signature Algorithm is not supported. Requested " + RAW_SIGNATURE + ".", e);
    }
  }

  private static DigestAlgorithm digestAlgorithm(AlgorithmSuite.Signature algorithm) {
    return algorithm == AlgorithmSuite.Signature.ECDSA_P256 ? DigestAlgorithm.SHA_256 : DigestAlgorithm.SHA_384;
  }

  private static int signatureLength(AlgorithmSuite.Signature algorithm) {
    return algorithm == AlgorithmSuite.Signature.ECDSA_P256 ? 71 : 103;
  }
}
