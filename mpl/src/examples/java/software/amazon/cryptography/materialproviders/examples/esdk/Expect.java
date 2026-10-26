// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.util.Arrays;

/** The checks the examples make; the ESDK examples use {@code assert}, which is off unless the JVM runs with -ea. */
final class Expect {

  private Expect() {}

  static void equal(byte[] expected, byte[] actual) {
    if (!Arrays.equals(expected, actual)) {
      throw new IllegalStateException("Decrypted bytes differ from the plaintext");
    }
  }

  static void isTrue(boolean condition, String what) {
    if (!condition) {
      throw new IllegalStateException("Expected: " + what);
    }
  }

  /** Runs {@code action} and returns what it threw; fails if it threw nothing or something else. */
  static <T extends Throwable> T failure(Class<T> type, Runnable action) {
    try {
      action.run();
    } catch (Throwable thrown) {
      if (type.isInstance(thrown)) {
        return type.cast(thrown);
      }
      throw new IllegalStateException("Expected " + type.getSimpleName() + " but got " + thrown, thrown);
    }
    throw new IllegalStateException("Expected " + type.getSimpleName() + " but nothing was thrown");
  }
}
