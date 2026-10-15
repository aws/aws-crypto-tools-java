// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl;

import java.util.Optional;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

//= spec/framework/algorithm-suites.md#supported-algorithm-suites-enum
//= type=implication
//# The Material Providers Library MUST provide
//# an ENUM that is the super set of all the [supported format algorithm suites enum](#supported-format-algorithm-suites-enum)
//# called the Algorithm Suite ENUM.
//
//= spec/framework/algorithm-suites.md#supported-algorithm-suites-enum
//= type=implication
//# This means that different formats MAY have duplicate Format Algorithm Suite ENUM.
//
//= spec/framework/algorithm-suites.md#overview
//= type=implication
//# The algorithm suite defines the behaviors [supported formats](#supported-formats) MUST follow for cryptographic operations.
//
//= spec/framework/algorithm-suites.md#gcm
//= type=implication
//# If specified to use GCM, the AWS Encryption SDK MUST use GCM with the following specifics:
//# - The internal block cipher is the encryption algorithm specified by the algorithm suite.
/**
 * The algorithm suites of the AWS Encryption SDK message format (ESDK) and the AWS Database Encryption SDK (DBE).
 *
 * <p>All suites encrypt with AES-GCM using a 12-byte IV and a 16-byte tag.
 * New suites may be added in later versions, so a {@code switch} over this enum needs a {@code default} branch.
 * {@link #toString()} is the constant name; {@link #binaryId()} is the 2-byte id written in messages.
 */
public enum AlgorithmSuite {
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
  ALG_AES_128_GCM_IV12_TAG16_NO_KDF(Format.ESDK, 0x0014, 1, 16, KeyDerivation.IDENTITY, false, null, false),
  ALG_AES_192_GCM_IV12_TAG16_NO_KDF(Format.ESDK, 0x0046, 1, 24, KeyDerivation.IDENTITY, false, null, false),
  ALG_AES_256_GCM_IV12_TAG16_NO_KDF(Format.ESDK, 0x0078, 1, 32, KeyDerivation.IDENTITY, false, null, false),
  ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256(Format.ESDK, 0x0114, 1, 16, KeyDerivation.HKDF_SHA256, false, null, false),
  ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256(Format.ESDK, 0x0146, 1, 24, KeyDerivation.HKDF_SHA256, false, null, false),
  ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256(Format.ESDK, 0x0178, 1, 32, KeyDerivation.HKDF_SHA256, false, null, false),
  ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256(Format.ESDK, 0x0214, 1, 16, KeyDerivation.HKDF_SHA256, false, Signature.ECDSA_P256, false),
  ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384(Format.ESDK, 0x0346, 1, 24, KeyDerivation.HKDF_SHA384, false, Signature.ECDSA_P384, false),
  ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384(Format.ESDK, 0x0378, 1, 32, KeyDerivation.HKDF_SHA384, false, Signature.ECDSA_P384, false),
  ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY(Format.ESDK, 0x0478, 2, 32, KeyDerivation.HKDF_SHA512, true, null, false),
  ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384(Format.ESDK, 0x0578, 2, 32, KeyDerivation.HKDF_SHA512, true, Signature.ECDSA_P384, false),
  ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384(Format.DBE, 0x6700, 1, 32, KeyDerivation.HKDF_SHA512, true, null, true),
  ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384(Format.DBE, 0x6701, 1, 32, KeyDerivation.HKDF_SHA512, true, Signature.ECDSA_P384, true);

  /** The message format a suite belongs to. */
  public enum Format {
    ESDK,
    DBE,
  }

  /** How the data key becomes the message encryption key. IDENTITY uses the data key as is. */
  public enum KeyDerivation {
    IDENTITY(null),
    HKDF_SHA256("HmacSHA256"),
    HKDF_SHA384("HmacSHA384"),
    HKDF_SHA512("HmacSHA512");

    private final String hmacAlgorithm;

    KeyDerivation(String hmacAlgorithm) {
      this.hmacAlgorithm = hmacAlgorithm;
    }

    /** The JCA {@code Mac} name of the HKDF's HMAC, for example {@code HmacSHA384}; empty for IDENTITY. */
    public Optional<String> hmacAlgorithm() {
      return Optional.ofNullable(hmacAlgorithm);
    }
  }

  /** Asymmetric signature over the whole message. */
  public enum Signature {
    ECDSA_P256("SHA256withECDSA", "secp256r1"),
    ECDSA_P384("SHA384withECDSA", "secp384r1");

    private final String jcaAlgorithm;
    private final String curveName;

    Signature(String jcaAlgorithm, String curveName) {
      this.jcaAlgorithm = jcaAlgorithm;
      this.curveName = curveName;
    }

    /** The JCA {@code Signature} name, for example {@code SHA384withECDSA}. */
    public String jcaAlgorithm() {
      return jcaAlgorithm;
    }

    /** The JCA name of the curve, for {@code ECGenParameterSpec}: {@code secp256r1} or {@code secp384r1}. */
    public String curveName() {
      return curveName;
    }
  }

  private final Format format;
  private final int binaryId;
  private final int messageVersion;
  private final int dataKeyLength;
  private final KeyDerivation keyDerivation;
  private final boolean committing;
  private final Signature signature;
  private final boolean symmetricSigning;

  //= spec/framework/algorithm-suites.md#structure
  //= type=implication
  //# The fields described below are REQUIRED to be specified by algorithm suites, unless otherwise specified.
  AlgorithmSuite(
    Format format,
    int binaryId,
    int messageVersion,
    int dataKeyLength,
    KeyDerivation keyDerivation,
    boolean committing,
    Signature signature,
    boolean symmetricSigning
  ) {
    this.format = format;
    this.binaryId = binaryId;
    this.messageVersion = messageVersion;
    this.dataKeyLength = dataKeyLength;
    this.keyDerivation = keyDerivation;
    this.committing = committing;
    this.signature = signature;
    this.symmetricSigning = symmetricSigning;
  }

  /**
   * The suite with the given 2-byte message id.
   *
   * @throws software.amazon.cryptography.mpl.exceptions.ValidationException if no suite has that id
   */
  public static AlgorithmSuite fromBinaryId(byte[] binaryId) {
    if (binaryId.length != 2) {
      throw new ValidationException("Invalid BinaryId");
    }
    return fromBinaryId(((binaryId[0] & 0xFF) << 8) | (binaryId[1] & 0xFF));
  }

  /**
   * The suite with the given id, the 2-byte message id read as an unsigned big-endian number (0x0478, 0x6701).
   *
   * @throws software.amazon.cryptography.mpl.exceptions.ValidationException if no suite has that id
   */
  public static AlgorithmSuite fromBinaryId(int id) {
    for (AlgorithmSuite suite : values()) {
      if (suite.binaryId == id) {
        return suite;
      }
    }
    throw new ValidationException("Invalid BinaryId");
  }

  public Format format() {
    return format;
  }

  /** The 2-byte id, big-endian, as written in the message header. A new array on every call. */
  public byte[] binaryId() {
    return new byte[] { (byte) (binaryId >> 8), (byte) binaryId };
  }

  public int messageVersion() {
    return messageVersion;
  }

  /** Length in bytes of the plaintext data key, which is also the AES key length. */
  public int dataKeyLength() {
    return dataKeyLength;
  }

  /** Always 12: every suite uses AES-GCM with a 12-byte IV. */
  public int ivLength() {
    return 12;
  }

  /** Always 16: every suite uses a 16-byte AES-GCM tag. */
  public int tagLength() {
    return 16;
  }

  public KeyDerivation keyDerivation() {
    return keyDerivation;
  }

  /** Salt length of the key derivation: 32 for committing suites (the message id), otherwise 0. */
  public int kdfSaltLength() {
    return committing ? 32 : 0;
  }

  /** Length of the commitment key in the message header: 32 for committing suites, otherwise 0. */
  public int commitmentKeyLength() {
    return committing ? 32 : 0;
  }

  /** Whether data keys are wrapped through an intermediate key; true exactly for the symmetric-signing (DBE) suites. */
  public boolean usesIntermediateKeyWrapping() {
    //= spec/framework/algorithm-suites.md#algorithm-suites-signature-settings
    //= type=implication
    //# An algorithm suite with a symmetric signature algorithm MUST use [intermediate key wrapping](#intermediate-key-wrapping).
    //
    //= spec/framework/algorithm-suites.md#symmetric-signature-algorithm
    //# - The algorithm suite MUST also use [Intermediate Key Wrapping](#intermediate-key-wrapping).
    return symmetricSigning;
  }

  /** Whether messages carry a key commitment (derived with HKDF-SHA-512 and a 32-byte salt). */
  public boolean isCommitting() {
    return committing;
  }

  /** The JCA {@code Mac} name of the HKDF that derives the key commitment: {@code HmacSHA512}; empty if not committing. */
  public Optional<String> commitmentHmacAlgorithm() {
    return committing ? Optional.of("HmacSHA512") : Optional.empty();
  }

  //= spec/framework/algorithm-suites.md#asymmetric-signature-algorithm
  //= type=implication
  //# This field is OPTIONAL.
  public Optional<Signature> signature() {
    return Optional.ofNullable(signature);
  }

  public boolean isSigning() {
    return signature != null;
  }

  //= spec/framework/algorithm-suites.md#symmetric-signature-algorithm
  //= type=implication
  //# This field is OPTIONAL.
  /**
   * Whether the suite signs with HMAC-SHA-384 per encrypted data key (DBE suites).
   * Such suites also wrap data keys with intermediate key wrapping.
   */
  public boolean isSymmetricSigning() {
    return symmetricSigning;
  }

  /** The JCA {@code Mac} name of the symmetric signature: {@code HmacSHA384}; empty unless {@link #isSymmetricSigning()}. */
  public Optional<String> symmetricSignatureHmacAlgorithm() {
    return symmetricSigning ? Optional.of("HmacSHA384") : Optional.empty();
  }
}
