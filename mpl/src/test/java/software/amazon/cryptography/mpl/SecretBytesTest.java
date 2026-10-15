// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.mpl.internal.SecretBytesAccess;

// Only library code reads a secret's own array.
class SecretBytesTest {

  @Test
  void noPublicMethodHandsOutTheArray() {
    for (Method method : SecretBytes.class.getDeclaredMethods()) {
      for (Class<?> parameter : method.getParameterTypes()) {
        if (Modifier.isPublic(method.getModifiers()) && Function.class.isAssignableFrom(parameter)) {
          throw new AssertionError("public method takes a function: " + method);
        }
      }
    }
  }

  @Test
  void theInternalReaderSeesTheBytesAndCannotBeReplaced() {
    SecretBytes secret = SecretBytes.copyOf(new byte[] { 1, 2, 3 });
    assertArrayEquals(new byte[] { 1, 2, 3 }, SecretBytesAccess.apply(secret, byte[]::clone));
    // The secret's own array, not a copy that would need clearing.
    assertSame(SecretBytesAccess.apply(secret, bytes -> bytes), SecretBytesAccess.apply(secret, bytes -> bytes));
    IllegalStateException e = assertThrows(
      IllegalStateException.class,
      () ->
        SecretBytesAccess.register(
          new SecretBytesAccess.Reader() {
            @Override
            public <R> R apply(SecretBytes s, Function<byte[], R> use) {
              return use.apply(new byte[0]);
            }
          }
        )
    );
    assertEquals("SecretBytes reader already registered", e.getMessage());
    assertArrayEquals(new byte[] { 1, 2, 3 }, SecretBytesAccess.apply(secret, byte[]::clone));
    secret.destroy();
    assertThrows(IllegalStateException.class, () -> SecretBytesAccess.apply(secret, byte[]::clone));
  }
}
