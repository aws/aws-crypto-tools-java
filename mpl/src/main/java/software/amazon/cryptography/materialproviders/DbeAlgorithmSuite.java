// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import java.util.Optional;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

//= spec/framework/algorithm-suites.md#supported-format-algorithm-suites-enum
//= type=implication
//# The Material Providers Library MUST provide
//# a set of algorithm suite ENUM for each [supported format](#supported-format).
/**
 * The algorithm suites of the AWS Database Encryption SDK; ids 0x6700 and 0x6701. They sign with HMAC-SHA-384 per encrypted data key.
 * More constants may be added; a {@code switch} needs a {@code default} branch.
 */
public enum DbeAlgorithmSuite implements AlgorithmSuite {
  ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384(0x6700, 1, 32, KeyDerivation.HKDF_SHA512, true, null),
  ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384(0x6701, 1, 32, KeyDerivation.HKDF_SHA512, true, Signature.ECDSA_P384);

  private final int binaryId;
  private final int messageVersion;
  private final int dataKeyLength;
  private final KeyDerivation keyDerivation;
  private final boolean committing;
  private final Signature signature;

  //= spec/framework/algorithm-suites.md#structure
  //= type=implication
  //# The fields described below are REQUIRED to be specified by algorithm suites, unless otherwise specified.
  DbeAlgorithmSuite(int binaryId, int messageVersion, int dataKeyLength, KeyDerivation keyDerivation, boolean committing, Signature signature) {
    this.binaryId = binaryId;
    this.messageVersion = messageVersion;
    this.dataKeyLength = dataKeyLength;
    this.keyDerivation = keyDerivation;
    this.committing = committing;
    this.signature = signature;
  }

  /**
   * The DBE suite with the given 2-byte message id.
   *
   * @throws ValidationException if no DBE suite has that id
   */
  public static DbeAlgorithmSuite fromBinaryId(byte[] binaryId) {
    if (binaryId.length != 2) {
      throw new ValidationException("Invalid BinaryId");
    }
    return fromBinaryId(((binaryId[0] & 0xFF) << 8) | (binaryId[1] & 0xFF));
  }

  /**
   * The DBE suite with the given id, the 2-byte message id read as an unsigned big-endian number.
   *
   * @throws ValidationException if no DBE suite has that id
   */
  public static DbeAlgorithmSuite fromBinaryId(int id) {
    for (DbeAlgorithmSuite suite : values()) {
      if (suite.binaryId == id) {
        return suite;
      }
    }
    throw new ValidationException("Invalid BinaryId");
  }

  @Override
  public Format format() {
    return Format.DBE;
  }

  @Override
  public byte[] binaryId() {
    return new byte[] { (byte) (binaryId >> 8), (byte) binaryId };
  }

  @Override
  public int messageVersion() {
    return messageVersion;
  }

  @Override
  public int dataKeyLength() {
    return dataKeyLength;
  }

  @Override
  public KeyDerivation keyDerivation() {
    return keyDerivation;
  }

  @Override
  public boolean isCommitting() {
    return committing;
  }

  @Override
  public Optional<Signature> signature() {
    return Optional.ofNullable(signature);
  }

  @Override
  public boolean isSymmetricSigning() {
    return true;
  }
}
