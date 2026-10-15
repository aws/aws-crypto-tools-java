// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal;

import java.util.function.Function;
import software.amazon.cryptography.mpl.SecretBytes;

/**
 * Zero-copy reads of {@link SecretBytes} for library code, which keeps the array local to the call.
 * The public class registers its reader when it loads.
 */
public final class SecretBytesAccess {

  /** Runs {@code use} on the secret's own array. */
  public interface Reader {
    <R> R apply(SecretBytes secret, Function<byte[], R> use);
  }

  private static volatile Reader reader;

  private SecretBytesAccess() {}

  /** @throws IllegalStateException if a reader is already registered, so no other code can replace it */
  public static synchronized void register(Reader secretReader) {
    if (reader != null) {
      throw new IllegalStateException("SecretBytes reader already registered");
    }
    reader = secretReader;
  }

  /** {@code use} must not keep, modify, or leak the array. */
  public static <R> R apply(SecretBytes secret, Function<byte[], R> use) {
    try {
      Class.forName(SecretBytes.class.getName(), true, SecretBytes.class.getClassLoader());
    } catch (ClassNotFoundException e) {
      throw new IllegalStateException(e);
    }
    return reader.apply(secret, use);
  }
}
