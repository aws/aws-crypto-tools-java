// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.primitives;

import java.util.Arrays;

/** Helpers for secrets held in byte arrays. */
public final class Bytes {

  private Bytes() {}

  /** Overwrites a secret held in a local copy once it is no longer needed. */
  public static void zero(byte[] secret) {
    if (secret != null) {
      Arrays.fill(secret, (byte) 0);
    }
  }
}
