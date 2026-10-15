// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Destroyable;

/**
 * Secret key material: plaintext data keys, signing keys, wrapping keys, branch keys.
 *
 * <p>Holds its own copy of the bytes. {@link #destroy()} overwrites them; any later access throws
 * {@link IllegalStateException}. Destroying is optional: it narrows how long a secret stays in memory,
 * but the JVM can still hold copies (JCA keys made by {@link #toSecretKey}, garbage-collected arrays),
 * so treat it as defense in depth, not a guarantee.
 *
 * <p>Ownership: whatever creates a {@code SecretBytes} owns it and may destroy it.
 * Builders and {@code with...} methods that take one copy it, so the caller keeps ownership of its own.
 * Accessors such as {@code EncryptionMaterials.plaintextDataKey()} return the object's own instance:
 * read it, but do not destroy it; destroy the owning object instead.
 *
 * <p>{@link #toString()} never shows the bytes. {@link #equals} is identity; compare contents with
 * {@link #contentEquals}, which runs in constant time. Thread-safe.
 */
public final class SecretBytes implements Destroyable, AutoCloseable {

  private final byte[] bytes;
  private volatile boolean destroyed;

  private SecretBytes(byte[] bytes) {
    this.bytes = bytes;
  }

  /** A copy of {@code bytes}; the caller keeps ownership of, and should clear, its array. */
  public static SecretBytes copyOf(byte[] bytes) {
    return new SecretBytes(bytes.clone());
  }

  /** An independent copy, owned by the caller. */
  public SecretBytes copy() {
    checkLive();
    return new SecretBytes(bytes.clone());
  }

  /** {@code length} bytes from a SecureRandom. */
  public static SecretBytes random(int length) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  public int length() {
    checkLive();
    return bytes.length;
  }

  /** A copy of the bytes. The caller owns the copy and should clear it after use. */
  public byte[] toByteArray() {
    checkLive();
    return bytes.clone();
  }

  /** The bytes as a JCA key, for example {@code toSecretKey("AES")}. The JCA key is a separate copy. */
  public SecretKey toSecretKey(String algorithm) {
    checkLive();
    return new SecretKeySpec(bytes, algorithm);
  }

  /** Whether both hold the same bytes; takes the same time for any two values of equal length. */
  public boolean contentEquals(SecretBytes other) {
    Objects.requireNonNull(other);
    checkLive();
    other.checkLive();
    return MessageDigest.isEqual(bytes, other.bytes);
  }

  @Override
  public void destroy() {
    destroyed = true;
    Arrays.fill(bytes, (byte) 0);
  }

  @Override
  public boolean isDestroyed() {
    return destroyed;
  }

  /** Same as {@link #destroy()}, so a try-with-resources block clears the secret. */
  @Override
  public void close() {
    destroy();
  }

  @Override
  public String toString() {
    return destroyed ? "SecretBytes[destroyed]" : "SecretBytes[" + bytes.length + " bytes]";
  }

  private void checkLive() {
    if (destroyed) {
      throw new IllegalStateException("SecretBytes was destroyed");
    }
  }
}
