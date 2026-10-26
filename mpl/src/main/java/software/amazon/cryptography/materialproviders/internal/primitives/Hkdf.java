// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.primitives;

import javax.crypto.Mac;

/** RFC 5869 HKDF, per HKDF/HKDF.dfy. Callers validate lengths first, as WrappedHKDF.dfy does. */
public final class Hkdf {

  private Hkdf() {}

  /** PRK = HMAC(salt, ikm); a null salt means HashLen zero bytes. */
  public static byte[] extract(DigestAlgorithm algorithm, byte[] salt, byte[] ikm) {
    byte[] key = salt != null ? salt : new byte[Digests.length(algorithm)];
    return Digests.hmac(algorithm, key, ikm);
  }

  /** OKM = first {@code length} bytes of T(1) | T(2) | ..., where T(i) = HMAC(prk, T(i-1) | info | i). */
  public static byte[] expand(DigestAlgorithm algorithm, byte[] prk, byte[] info, int length) {
    int hashLength = Digests.length(algorithm);
    int blocks = (length + hashLength - 1) / hashLength;
    Mac mac = Digests.mac(algorithm, prk);
    byte[] okm = new byte[length];
    byte[] previous = new byte[0];
    for (int i = 1; i <= blocks; i++) {
      mac.update(previous);
      mac.update(info);
      mac.update((byte) i);
      Bytes.zero(previous);
      previous = mac.doFinal();
      int offset = (i - 1) * hashLength;
      System.arraycopy(previous, 0, okm, offset, Math.min(hashLength, length - offset));
    }
    Bytes.zero(previous);
    return okm;
  }

  public static byte[] hkdf(DigestAlgorithm algorithm, byte[] salt, byte[] ikm, byte[] info, int length) {
    byte[] prk = extract(algorithm, salt, ikm);
    try {
      return expand(algorithm, prk, info, length);
    } finally {
      Bytes.zero(prk);
    }
  }
}
