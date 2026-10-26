// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.primitives;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** SHA-2 digests and HMAC through the default JCE providers. */
public final class Digests {

  private Digests() {}

  public static int length(DigestAlgorithm algorithm) {
    switch (algorithm) {
      case SHA_256:
        return 32;
      case SHA_384:
        return 48;
      case SHA_512:
        return 64;
      default:
        throw new IllegalArgumentException("unknown digest algorithm " + algorithm);
    }
  }

  public static byte[] digest(DigestAlgorithm algorithm, byte[] message) {
    return messageDigest(algorithm).digest(message);
  }

  public static byte[] hmac(DigestAlgorithm algorithm, byte[] key, byte[] message) {
    Mac mac = mac(algorithm, key);
    return mac.doFinal(message);
  }

  /**
   * A Mac keyed with {@code key}. {@code doFinal} resets it and keeps the key,
   * so one instance computes several MACs under the same key.
   * The caller's key array is not retained.
   */
  static Mac mac(DigestAlgorithm algorithm, byte[] key) {
    String name = hmacName(algorithm);
    try {
      Mac mac = Mac.getInstance(name);
      mac.init(new SecretKeySpec(key, name));
      return mac;
    } catch (GeneralSecurityException e) {
      // Every DigestAlgorithm has an HMAC in the default providers, and HMAC accepts any non-empty key.
      throw new IllegalStateException("HMAC unavailable: " + name, e);
    }
  }

  private static MessageDigest messageDigest(DigestAlgorithm algorithm) {
    String name;
    switch (algorithm) {
      case SHA_256:
        name = "SHA-256";
        break;
      case SHA_384:
        name = "SHA-384";
        break;
      case SHA_512:
        name = "SHA-512";
        break;
      default:
        throw new IllegalArgumentException("unknown digest algorithm " + algorithm);
    }
    try {
      return MessageDigest.getInstance(name);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("digest unavailable: " + name, e);
    }
  }

  private static String hmacName(DigestAlgorithm algorithm) {
    switch (algorithm) {
      case SHA_256:
        return "HmacSHA256";
      case SHA_384:
        return "HmacSHA384";
      case SHA_512:
        return "HmacSHA512";
      default:
        throw new IllegalArgumentException("unknown digest algorithm " + algorithm);
    }
  }
}
