// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import java.util.Optional;

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
 * An algorithm suite of the AWS Encryption SDK message format ({@link EsdkAlgorithmSuite}) or of the AWS Database
 * Encryption SDK ({@link DbeAlgorithmSuite}). The two enums are the only implementations; not for implementation by
 * callers, and the materials and requests reject any other with
 * {@link software.amazon.cryptography.materialproviders.exceptions.ValidationException}.
 *
 * <p>All suites encrypt with AES-GCM using a 12-byte IV and a 16-byte tag.
 * {@link #name()} is the constant name; {@link #binaryId()} is the 2-byte id written in messages.
 * To read an id from a message, use the lookup of its format: {@link EsdkAlgorithmSuite#fromBinaryId(byte[])} or
 * {@link DbeAlgorithmSuite#fromBinaryId(byte[])}.
 */
public interface AlgorithmSuite {
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

  /** The constant name, for example {@code ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY}. */
  String name();

  Format format();

  /** The 2-byte id, big-endian, as written in the message header. A new array on every call. */
  byte[] binaryId();

  int messageVersion();

  /** Length in bytes of the plaintext data key, which is also the AES key length. */
  int dataKeyLength();

  /** Always 12: every suite uses AES-GCM with a 12-byte IV. */
  default int ivLength() {
    return 12;
  }

  /** Always 16: every suite uses a 16-byte AES-GCM tag. */
  default int tagLength() {
    return 16;
  }

  KeyDerivation keyDerivation();

  /** Salt length of the key derivation: 32 for committing suites (the message id), otherwise 0. */
  default int kdfSaltLength() {
    return isCommitting() ? 32 : 0;
  }

  /** Length of the commitment key in the message header: 32 for committing suites, otherwise 0. */
  default int commitmentKeyLength() {
    return isCommitting() ? 32 : 0;
  }

  /** Whether data keys are wrapped through an intermediate key; true exactly for the symmetric-signing (DBE) suites. */
  default boolean usesIntermediateKeyWrapping() {
    //= spec/framework/algorithm-suites.md#algorithm-suites-signature-settings
    //= type=implication
    //# An algorithm suite with a symmetric signature algorithm MUST use [intermediate key wrapping](#intermediate-key-wrapping).
    //
    //= spec/framework/algorithm-suites.md#symmetric-signature-algorithm
    //# - The algorithm suite MUST also use [Intermediate Key Wrapping](#intermediate-key-wrapping).
    return isSymmetricSigning();
  }

  /** Whether messages carry a key commitment (derived with HKDF-SHA-512 and a 32-byte salt). */
  boolean isCommitting();

  /** The JCA {@code Mac} name of the HKDF that derives the key commitment: {@code HmacSHA512}; empty if not committing. */
  default Optional<String> commitmentHmacAlgorithm() {
    return isCommitting() ? Optional.of("HmacSHA512") : Optional.empty();
  }

  //= spec/framework/algorithm-suites.md#asymmetric-signature-algorithm
  //= type=implication
  //# This field is OPTIONAL.
  Optional<Signature> signature();

  default boolean isSigning() {
    return signature().isPresent();
  }

  //= spec/framework/algorithm-suites.md#symmetric-signature-algorithm
  //= type=implication
  //# This field is OPTIONAL.
  /**
   * Whether the suite signs with HMAC-SHA-384 per encrypted data key (DBE suites).
   * Such suites also wrap data keys with intermediate key wrapping.
   */
  boolean isSymmetricSigning();

  /** The JCA {@code Mac} name of the symmetric signature: {@code HmacSHA384}; empty unless {@link #isSymmetricSigning()}. */
  default Optional<String> symmetricSignatureHmacAlgorithm() {
    return isSymmetricSigning() ? Optional.of("HmacSHA384") : Optional.empty();
  }
}
