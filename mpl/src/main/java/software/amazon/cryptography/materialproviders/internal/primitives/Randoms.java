// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.primitives;

import java.security.SecureRandom;

/** Random bytes from a per-thread SecureRandom. */
public final class Randoms {

  // SecureRandom is costly to create and synchronizes internally; one per thread avoids both costs.
  private static final ThreadLocal<SecureRandom> LOCAL = ThreadLocal.withInitial(() -> {
    SecureRandom random = new SecureRandom();
    // Draw once so seeding happens here, not on a caller's first request.
    random.nextBoolean();
    return random;
  });

  private Randoms() {}

  /** This thread's SecureRandom, for key generation and signing. */
  static SecureRandom secureRandom() {
    return LOCAL.get();
  }

  public static byte[] generate(int length) {
    byte[] bytes = new byte[length];
    LOCAL.get().nextBytes(bytes);
    return bytes;
  }
}
