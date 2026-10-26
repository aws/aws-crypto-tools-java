// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders.internal;

import java.nio.ByteBuffer;

/** Test adapter: conversions between the old API's {@link ByteBuffer} values and the native byte arrays. */
public final class Buffers {

  private Buffers() {}

  /**
   * Copies bytes {@code [0, limit)} of the buffer, ignoring its position, without changing its state.
   * The Dafny-based MPL read every ByteBuffer input this way: a caller that passes a buffer after reading from it
   * still has the whole value used.
   */
  public static byte[] toArray(ByteBuffer buffer) {
    byte[] copy = new byte[buffer.limit()];
    for (int i = 0; i < copy.length; i++) {
      copy[i] = buffer.get(i);
    }
    return copy;
  }

  /** Wraps a fresh copy, so a caller mutating the result cannot change native state. */
  public static ByteBuffer toBuffer(byte[] bytes) {
    return ByteBuffer.wrap(bytes.clone());
  }
}
