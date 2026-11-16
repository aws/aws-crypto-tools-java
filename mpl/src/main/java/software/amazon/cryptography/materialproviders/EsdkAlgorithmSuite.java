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
 * The algorithm suites of the AWS Encryption SDK message format; ids 0x0014 to 0x0578.
 * More constants may be added; a {@code switch} needs a {@code default} branch.
 */
public enum EsdkAlgorithmSuite implements AlgorithmSuite {
  //= spec/framework/algorithm-suites.md#supported-algorithm-suites
  //= type=implication
  //# The value `00 00` is reserved
  //# and MUST NOT be used
  //# as an Algorithm Suite ID in the future.
  //
  //= spec/framework/algorithm-suites.md#supported-algorithm-suites
  //= type=implication
  //# Algorithm Suite ID MUST be a unique hex value across all supported algorithm suites.
  //
  //= spec/framework/algorithm-suites.md#algorithm-suite-id
  //= type=implication
  //# A 2-byte hex value that MUST uniquely identify an algorithm suite.
  ALG_AES_128_GCM_IV12_TAG16_NO_KDF(0x0014, 1, 16, KeyDerivation.IDENTITY, false, null),
  ALG_AES_192_GCM_IV12_TAG16_NO_KDF(0x0046, 1, 24, KeyDerivation.IDENTITY, false, null),
  ALG_AES_256_GCM_IV12_TAG16_NO_KDF(0x0078, 1, 32, KeyDerivation.IDENTITY, false, null),
  ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256(0x0114, 1, 16, KeyDerivation.HKDF_SHA256, false, null),
  ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256(0x0146, 1, 24, KeyDerivation.HKDF_SHA256, false, null),
  ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256(0x0178, 1, 32, KeyDerivation.HKDF_SHA256, false, null),
  ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256(0x0214, 1, 16, KeyDerivation.HKDF_SHA256, false, Signature.ECDSA_P256),
  ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384(0x0346, 1, 24, KeyDerivation.HKDF_SHA384, false, Signature.ECDSA_P384),
  ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384(0x0378, 1, 32, KeyDerivation.HKDF_SHA384, false, Signature.ECDSA_P384),
  ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY(0x0478, 2, 32, KeyDerivation.HKDF_SHA512, true, null),
  ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384(0x0578, 2, 32, KeyDerivation.HKDF_SHA512, true, Signature.ECDSA_P384);

  private final int binaryId;
  private final int messageVersion;
  private final int dataKeyLength;
  private final KeyDerivation keyDerivation;
  private final boolean committing;
  private final Signature signature;

  //= spec/framework/algorithm-suites.md#structure
  //= type=implication
  //# The fields described below are REQUIRED to be specified by algorithm suites, unless otherwise specified.
  EsdkAlgorithmSuite(int binaryId, int messageVersion, int dataKeyLength, KeyDerivation keyDerivation, boolean committing, Signature signature) {
    this.binaryId = binaryId;
    this.messageVersion = messageVersion;
    this.dataKeyLength = dataKeyLength;
    this.keyDerivation = keyDerivation;
    this.committing = committing;
    this.signature = signature;
  }

  /**
   * The ESDK suite with the given 2-byte message id.
   *
   * @throws ValidationException if no ESDK suite has that id
   */
  public static EsdkAlgorithmSuite fromBinaryId(byte[] binaryId) {
    if (binaryId.length != 2) {
      throw new ValidationException("Invalid BinaryId");
    }
    return fromBinaryId(((binaryId[0] & 0xFF) << 8) | (binaryId[1] & 0xFF));
  }

  /**
   * The ESDK suite with the given id, the 2-byte message id read as an unsigned big-endian number.
   *
   * @throws ValidationException if no ESDK suite has that id
   */
  public static EsdkAlgorithmSuite fromBinaryId(int id) {
    for (EsdkAlgorithmSuite suite : values()) {
      if (suite.binaryId == id) {
        return suite;
      }
    }
    throw new ValidationException("Invalid BinaryId");
  }

  @Override
  public Format format() {
    return Format.ESDK;
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
    return false;
  }
}
