// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.primitives;

import java.nio.ByteBuffer;
import javax.crypto.Mac;

/**
 * NIST SP 800-108 KDF in counter mode with HMAC, per KDF/KdfCtr.dfy.
 * The PRF input for block i is uint32(i) | fixedInput.
 * Callers validate the inputs first, as KdfCtr.dfy does.
 */
public final class KdfCounterMode {

  private KdfCounterMode() {}

  /** The fixed input SP 800-108 recommends: label | 0x00 | context | uint32(length in bits). */
  public static byte[] fixedInput(byte[] label, byte[] context, int length) {
    return ByteBuffer
      .allocate(label.length + 1 + context.length + 4)
      .put(label)
      .put((byte) 0x00)
      .put(context)
      .putInt(length * 8)
      .array();
  }

  public static byte[] derive(DigestAlgorithm algorithm, byte[] ikm, byte[] fixedInput, int length) {
    int macLength = Digests.length(algorithm);
    int blocks = (length + macLength - 1) / macLength;
    Mac mac = Digests.mac(algorithm, ikm);
    byte[] okm = new byte[length];
    for (int i = 1; i <= blocks; i++) {
      mac.update(ByteBuffer.allocate(4).putInt(i).array());
      mac.update(fixedInput);
      byte[] block = mac.doFinal();
      int offset = (i - 1) * macLength;
      System.arraycopy(block, 0, okm, offset, Math.min(macLength, length - offset));
      Bytes.zero(block);
    }
    return okm;
  }
}
