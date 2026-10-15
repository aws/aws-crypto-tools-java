// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal.primitives;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-GCM through the default JCE provider ("AES/GCM/NoPadding").
 * Each call gets its own Cipher: a Cipher is not thread-safe,
 * and JCE refuses to re-initialize one for GCM encryption with the same key and IV.
 * The JCE keeps its own copies of the key (SecretKeySpec clones it); those are not zeroed.
 */
public final class AesGcm {

  private AesGcm() {}

  /** Returns {ciphertext, tag}. */
  public static byte[][] encrypt(int tagLength, byte[] key, byte[] iv, byte[] plaintext, byte[] aad)
    throws GeneralSecurityException {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(tagLength * 8, iv));
    cipher.updateAAD(aad);
    byte[] output = cipher.doFinal(plaintext);
    int split = output.length - tagLength;
    return new byte[][] { Arrays.copyOfRange(output, 0, split), Arrays.copyOfRange(output, split, output.length) };
  }

  public static byte[] decrypt(int tagLength, byte[] key, byte[] iv, byte[] ciphertext, byte[] tag, byte[] aad)
    throws GeneralSecurityException {
    byte[] input = new byte[ciphertext.length + tag.length];
    System.arraycopy(ciphertext, 0, input, 0, ciphertext.length);
    System.arraycopy(tag, 0, input, ciphertext.length, tag.length);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(tagLength * 8, iv));
    cipher.updateAAD(aad);
    return cipher.doFinal(input);
  }
}
