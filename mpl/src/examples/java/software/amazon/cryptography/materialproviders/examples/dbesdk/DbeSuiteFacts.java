// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.dbesdk;

import software.amazon.cryptography.materialproviders.AlgorithmSuite;

/**
 * Integration example: the DB-ESDK header names its suite with one flavor byte.
 *
 * <p>The DB-ESDK's {@code structuredencryption.internal.AlgorithmSuite} record holds
 * {@code (flavor, hasEcdsaSignature, keyDerivationHmac, commitmentHmac, symmetricSignatureHmac, encryptionKeyLength,
 * commitmentKeyLength)}.
 * Every field but the flavor comes straight from {@link AlgorithmSuite}, the JCA names included:
 * {@code keyDerivation().hmacAlgorithm()}, {@code commitmentHmacAlgorithm()}, {@code symmetricSignatureHmacAlgorithm()}.
 */
public final class DbeSuiteFacts {

  // A DBE suite id is 0x67 followed by the header's flavor byte.
  private static final int DBE_ID_PREFIX = 0x6700;

  private DbeSuiteFacts() {}

  /**
   * The suite a DB-ESDK header names with its flavor byte; replaces the test server's hand-written switch.
   *
   * @throws software.amazon.cryptography.materialproviders.exceptions.ValidationException for an unknown flavor
   */
  public static AlgorithmSuite fromFlavor(byte flavor) {
    return AlgorithmSuite.fromBinaryId(DBE_ID_PREFIX | (flavor & 0xFF));
  }

  /** The flavor byte the DB-ESDK writes in its header. */
  public static byte flavor(AlgorithmSuite suite) {
    if (suite.format() != AlgorithmSuite.Format.DBE) {
      throw new IllegalArgumentException("Not a DBE suite: " + suite);
    }
    return suite.binaryId()[1];
  }
}
