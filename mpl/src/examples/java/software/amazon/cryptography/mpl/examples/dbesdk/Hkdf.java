// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples.dbesdk;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** RFC 5869 HKDF over a JCA HMAC, as the DB-ESDK has its own; Java 8 has no HKDF. */
final class Hkdf {

  private Hkdf() {}

  /** An empty salt means HashLen zero bytes (RFC 5869 sec. 2.2). */
  static byte[] derive(String hmacAlgorithm, byte[] salt, byte[] ikm, byte[] info, int length) {
    byte[] prk = null;
    try {
      Mac mac = Mac.getInstance(hmacAlgorithm);
      mac.init(new SecretKeySpec(salt.length == 0 ? new byte[mac.getMacLength()] : salt, hmacAlgorithm));
      prk = mac.doFinal(ikm);
      mac.init(new SecretKeySpec(prk, hmacAlgorithm));
      byte[] okm = new byte[length];
      byte[] block = new byte[0];
      for (int counter = 1, done = 0; done < length; counter++) {
        mac.update(block);
        mac.update(info);
        mac.update((byte) counter);
        block = mac.doFinal();
        int n = Math.min(block.length, length - done);
        System.arraycopy(block, 0, okm, done, n);
        done += n;
      }
      Arrays.fill(block, (byte) 0);
      return okm;
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(hmacAlgorithm + " unavailable", e);
    } finally {
      if (prk != null) {
        Arrays.fill(prk, (byte) 0);
      }
    }
  }
}
