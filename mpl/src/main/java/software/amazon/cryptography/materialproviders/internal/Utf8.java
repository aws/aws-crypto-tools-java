// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Comparator;

/** Strict UTF-8 for strings the message format stores as bytes (encryption context, provider ids). */
public final class Utf8 {

  /** Orders strings by their UTF-8 bytes, unsigned, shorter prefix first: the order the message format serializes in. */
  public static final Comparator<String> BYTE_ORDER = (a, b) -> compare(encode(a), encode(b));

  private Utf8() {}

  /** Whether {@code value} is well-formed UTF-16, so it has a UTF-8 encoding. */
  public static boolean isEncodable(String value) {
    try {
      StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(value));
      return true;
    } catch (CharacterCodingException e) {
      return false;
    }
  }

  /** The UTF-8 bytes of a well-formed string. */
  public static byte[] encode(String value) {
    try {
      ByteBuffer encoded = StandardCharsets.UTF_8
        .newEncoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .encode(CharBuffer.wrap(value));
      byte[] bytes = new byte[encoded.remaining()];
      encoded.get(bytes);
      return bytes;
    } catch (CharacterCodingException e) {
      throw new IllegalArgumentException("not well-formed UTF-16", e);
    }
  }

  /**
   * The string {@code bytes} encode, or null if they are not well-formed UTF-8
   * (for example a truncated sequence, an overlong form, or an encoded surrogate).
   */
  public static String decode(byte[] bytes) {
    try {
      return StandardCharsets.UTF_8
        .newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes))
        .toString();
    } catch (CharacterCodingException e) {
      return null;
    }
  }

  public static int compare(byte[] a, byte[] b) {
    int common = Math.min(a.length, b.length);
    for (int i = 0; i < common; i++) {
      int difference = (a[i] & 0xFF) - (b[i] & 0xFF);
      if (difference != 0) {
        return difference;
      }
    }
    return a.length - b.length;
  }
}
