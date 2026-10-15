// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal.primitives;

import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

/**
 * RSA key generation as the Dafny-based MPL's GenerateRSAKeyPair did it. Only the old-API test adapter offers
 * key generation; the native library does not.
 */
public final class RsaKeyGeneration {

  private static final int MIN_LENGTH_BITS = 81;
  private static final int MAX_GENERATED_LENGTH_BITS = 4096;
  private static final BigInteger PUBLIC_EXPONENT = BigInteger.valueOf(65537);
  private static final int PRIME_CERTAINTY = 256;
  private static final String KEY_GENERATION_FAILED = "Unable to create RSA Key Pair";

  private RsaKeyGeneration() {}

  /**
   * Returns {publicKeyPem, privateKeyPem}.
   *
   * @throws ValidationException if {@code lengthBits} is outside [81, 4096] or BouncyCastle cannot generate it;
   *   it cannot generate odd lengths
   */
  public static byte[][] generateKeyPair(int lengthBits) {
    if (lengthBits < MIN_LENGTH_BITS || lengthBits > MAX_GENERATED_LENGTH_BITS) {
      throw new ValidationException(KEY_GENERATION_FAILED);
    }
    AsymmetricCipherKeyPair pair;
    try {
      RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
      generator.init(new RSAKeyGenerationParameters(PUBLIC_EXPONENT, Randoms.secureRandom(), lengthBits, PRIME_CERTAINTY));
      pair = generator.generateKeyPair();
    } catch (RuntimeException e) {
      throw new ValidationException(KEY_GENERATION_FAILED, e);
    }
    try {
      byte[] privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(pair.getPrivate()).getEncoded();
      try {
        return new byte[][] {
          Pem.encode("PUBLIC KEY", SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pair.getPublic()).getEncoded()),
          Pem.encode("PRIVATE KEY", privateKeyInfo),
        };
      } finally {
        Bytes.zero(privateKeyInfo);
      }
    } catch (IOException e) {
      throw new IllegalStateException("encoding a generated RSA key failed", e);
    }
  }

}
