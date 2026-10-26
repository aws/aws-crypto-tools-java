// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders.internal;

import java.util.Arrays;
import java.util.Objects;
import software.amazon.cryptography.oldapi.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.AlgorithmSuiteInfo;
import software.amazon.cryptography.oldapi.materialproviders.model.AwsCryptographicMaterialProvidersException;
import software.amazon.cryptography.oldapi.materialproviders.model.DBEAlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.DIRECT_KEY_WRAPPING;
import software.amazon.cryptography.oldapi.materialproviders.model.DerivationAlgorithm;
import software.amazon.cryptography.oldapi.materialproviders.model.ECDSA;
import software.amazon.cryptography.oldapi.materialproviders.model.ESDKAlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.EdkWrappingAlgorithm;
import software.amazon.cryptography.oldapi.materialproviders.model.Encrypt;
import software.amazon.cryptography.oldapi.materialproviders.model.HKDF;
import software.amazon.cryptography.oldapi.materialproviders.model.IntermediateKeyWrapping;
import software.amazon.cryptography.oldapi.materialproviders.model.None;
import software.amazon.cryptography.oldapi.materialproviders.model.SignatureAlgorithm;
import software.amazon.cryptography.oldapi.materialproviders.model.SymmetricSignatureAlgorithm;
import software.amazon.cryptography.oldapi.primitives.model.AES_GCM;
import software.amazon.cryptography.oldapi.primitives.model.DigestAlgorithm;
import software.amazon.cryptography.oldapi.primitives.model.ECDSASignatureAlgorithm;

/**
 * The supported algorithm suites, per AlgorithmSuites.dfy.
 * Each constant is the single valid {@link AlgorithmSuiteInfo} for its id:
 * Dafny's LemmaAlgorithmSuiteIdImpliesEquality proves no other info satisfies AlgorithmSuite? for that id.
 */
public enum AlgorithmSuite {
  ESDK_ALG_AES_128_GCM_IV12_TAG16_NO_KDF(
    ESDKAlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_NO_KDF, 0x00, 0x14, 1, 16,
    Kdf.IDENTITY, Kdf.NONE, null, null
  ),
  ESDK_ALG_AES_192_GCM_IV12_TAG16_NO_KDF(
    ESDKAlgorithmSuiteId.ALG_AES_192_GCM_IV12_TAG16_NO_KDF, 0x00, 0x46, 1, 24,
    Kdf.IDENTITY, Kdf.NONE, null, null
  ),
  ESDK_ALG_AES_256_GCM_IV12_TAG16_NO_KDF(
    ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_NO_KDF, 0x00, 0x78, 1, 32,
    Kdf.IDENTITY, Kdf.NONE, null, null
  ),
  ESDK_ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256(
    ESDKAlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256, 0x01, 0x14, 1, 16,
    Kdf.HKDF_SHA_256, Kdf.NONE, null, null
  ),
  ESDK_ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256(
    ESDKAlgorithmSuiteId.ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256, 0x01, 0x46, 1, 24,
    Kdf.HKDF_SHA_256, Kdf.NONE, null, null
  ),
  ESDK_ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256(
    ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256, 0x01, 0x78, 1, 32,
    Kdf.HKDF_SHA_256, Kdf.NONE, null, null
  ),
  ESDK_ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256(
    ESDKAlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256, 0x02, 0x14, 1, 16,
    Kdf.HKDF_SHA_256, Kdf.NONE, ECDSASignatureAlgorithm.ECDSA_P256, null
  ),
  ESDK_ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384(
    ESDKAlgorithmSuiteId.ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, 0x03, 0x46, 1, 24,
    Kdf.HKDF_SHA_384, Kdf.NONE, ECDSASignatureAlgorithm.ECDSA_P384, null
  ),
  ESDK_ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384(
    ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, 0x03, 0x78, 1, 32,
    Kdf.HKDF_SHA_384, Kdf.NONE, ECDSASignatureAlgorithm.ECDSA_P384, null
  ),
  ESDK_ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY(
    ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, 0x04, 0x78, 2, 32,
    Kdf.HKDF_SHA_512, Kdf.HKDF_SHA_512, null, null
  ),
  ESDK_ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384(
    ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, 0x05, 0x78, 2, 32,
    Kdf.HKDF_SHA_512, Kdf.HKDF_SHA_512, ECDSASignatureAlgorithm.ECDSA_P384, null
  ),
  DBE_ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384(
    DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384, 0x67, 0x00, 1, 32,
    Kdf.HKDF_SHA_512, Kdf.HKDF_SHA_512, null, DigestAlgorithm.SHA_384
  ),
  DBE_ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384(
    DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384, 0x67, 0x01, 1, 32,
    Kdf.HKDF_SHA_512, Kdf.HKDF_SHA_512, ECDSASignatureAlgorithm.ECDSA_P384, DigestAlgorithm.SHA_384
  );

  // Every suite encrypts with AES-GCM using a 12-byte IV and a 16-byte tag.
  private static final int IV_LENGTH = 12;
  private static final int TAG_LENGTH = 16;

  /**
   * A key derivation choice.
   * IDENTITY and NONE are distinct because the kdf field uses IDENTITY for "use the data key as is"
   * while the commitment field uses NONE for "no commitment key".
   */
  enum Kdf {
    IDENTITY(null, 0),
    NONE(null, 0),
    HKDF_SHA_256(DigestAlgorithm.SHA_256, 0),
    HKDF_SHA_384(DigestAlgorithm.SHA_384, 0),
    HKDF_SHA_512(DigestAlgorithm.SHA_512, 32);

    final DigestAlgorithm hmac;
    final int saltLength;

    Kdf(DigestAlgorithm hmac, int saltLength) {
      this.hmac = hmac;
      this.saltLength = saltLength;
    }

    DerivationAlgorithm toModel(int keyLength) {
      switch (this) {
        case IDENTITY:
          return DerivationAlgorithm
            .builder()
            .IDENTITY(software.amazon.cryptography.oldapi.materialproviders.model.IDENTITY.builder().build())
            .build();
        case NONE:
          return DerivationAlgorithm.builder().None(None.builder().build()).build();
        default:
          return DerivationAlgorithm
            .builder()
            .HKDF(
              HKDF
                .builder()
                .hmac(hmac)
                .saltLength(saltLength)
                .inputKeyLength(keyLength)
                .outputKeyLength(keyLength)
                .build()
            )
            .build();
      }
    }
  }

  private final ESDKAlgorithmSuiteId esdkId;
  private final DBEAlgorithmSuiteId dbeId;
  private final byte[] binaryId;
  private final int messageVersion;
  private final int keyLength;
  private final Kdf kdf;
  private final Kdf commitment;
  private final ECDSASignatureAlgorithm signature;
  private final DigestAlgorithm symmetricSignature;

  AlgorithmSuite(
    ESDKAlgorithmSuiteId id,
    int binaryIdHigh,
    int binaryIdLow,
    int messageVersion,
    int keyLength,
    Kdf kdf,
    Kdf commitment,
    ECDSASignatureAlgorithm signature,
    DigestAlgorithm symmetricSignature
  ) {
    this(id, null, binaryIdHigh, binaryIdLow, messageVersion, keyLength, kdf, commitment, signature, symmetricSignature);
  }

  AlgorithmSuite(
    DBEAlgorithmSuiteId id,
    int binaryIdHigh,
    int binaryIdLow,
    int messageVersion,
    int keyLength,
    Kdf kdf,
    Kdf commitment,
    ECDSASignatureAlgorithm signature,
    DigestAlgorithm symmetricSignature
  ) {
    this(null, id, binaryIdHigh, binaryIdLow, messageVersion, keyLength, kdf, commitment, signature, symmetricSignature);
  }

  AlgorithmSuite(
    ESDKAlgorithmSuiteId esdkId,
    DBEAlgorithmSuiteId dbeId,
    int binaryIdHigh,
    int binaryIdLow,
    int messageVersion,
    int keyLength,
    Kdf kdf,
    Kdf commitment,
    ECDSASignatureAlgorithm signature,
    DigestAlgorithm symmetricSignature
  ) {
    this.esdkId = esdkId;
    this.dbeId = dbeId;
    this.binaryId = new byte[] { (byte) binaryIdHigh, (byte) binaryIdLow };
    this.messageVersion = messageVersion;
    this.keyLength = keyLength;
    this.kdf = kdf;
    this.commitment = commitment;
    this.signature = signature;
    this.symmetricSignature = symmetricSignature;
  }

  /** The suite for a public id; every id names exactly one suite. */
  public static AlgorithmSuite of(AlgorithmSuiteId id) {
    for (AlgorithmSuite suite : values()) {
      if (suite.esdkId != null && suite.esdkId == id.ESDK() || suite.dbeId != null && suite.dbeId == id.DBE()) {
        return suite;
      }
    }
    throw new IllegalStateException("unreachable: AlgorithmSuiteId with no suite");
  }

  /** The suite with the given 2-byte message format id. */
  public static AlgorithmSuite ofBinaryId(byte[] binaryId) {
    software.amazon.cryptography.materialproviders.AlgorithmSuite core;
    try {
      core = software.amazon.cryptography.materialproviders.AlgorithmSuite.fromBinaryId(binaryId);
    } catch (software.amazon.cryptography.materialproviders.exceptions.ValidationException e) {
      throw AwsCryptographicMaterialProvidersException.builder().message(e.getMessage()).build();
    }
    for (AlgorithmSuite suite : values()) {
      if (Arrays.equals(suite.binaryId, core.binaryId())) {
        return suite;
      }
    }
    throw new IllegalStateException("unreachable: no table entry for " + core);
  }

  public int encryptionKeyLength() {
    return keyLength;
  }

  public boolean isSigning() {
    return signature != null;
  }

  public boolean hasSymmetricSignature() {
    return symmetricSignature != null;
  }

  public boolean isCommitting() {
    return commitment != Kdf.NONE;
  }

  AlgorithmSuiteId id() {
    return esdkId != null
      ? AlgorithmSuiteId.builder().ESDK(esdkId).build()
      : AlgorithmSuiteId.builder().DBE(dbeId).build();
  }

  /** A new public description of this suite; each call returns a separate object graph. */
  /** The description built from the native enum, which is what the differential tests check. */
  public AlgorithmSuiteInfo info() {
    return Convert.info(Convert.suite(id()));
  }

  /** The description from this test table, kept to check the native enum against. */
  AlgorithmSuiteInfo tableInfo() {
    return AlgorithmSuiteInfo
      .builder()
      .id(id())
      .binaryId(Buffers.toBuffer(binaryId))
      .messageVersion(messageVersion)
      .encrypt(aesGcm(keyLength))
      .kdf(kdf.toModel(keyLength))
      .commitment(commitment.toModel(keyLength))
      .signature(
        signature == null
          ? SignatureAlgorithm.builder().None(None.builder().build()).build()
          : SignatureAlgorithm.builder().ECDSA(ECDSA.builder().curve(signature).build()).build()
      )
      .symmetricSignature(
        symmetricSignature == null
          ? SymmetricSignatureAlgorithm.builder().None(None.builder().build()).build()
          : SymmetricSignatureAlgorithm.builder().HMAC(symmetricSignature).build()
      )
      .edkWrapping(edkWrapping())
      .build();
  }

  /**
   * Whether {@code info} is exactly this library's description of the suite it names.
   * Equivalent to Dafny's AlgorithmSuite? predicate; see the class comment.
   */
  public static boolean isValid(AlgorithmSuiteInfo info) {
    return Equality.same(info, of(info.id()).info());
  }

  // Only the DBE suites use intermediate key wrapping.
  private EdkWrappingAlgorithm edkWrapping() {
    if (dbeId == null) {
      return EdkWrappingAlgorithm.builder().DIRECT_KEY_WRAPPING(DIRECT_KEY_WRAPPING.builder().build()).build();
    }
    return EdkWrappingAlgorithm
      .builder()
      .IntermediateKeyWrapping(
        IntermediateKeyWrapping
          .builder()
          .keyEncryptionKeyKdf(kdf.toModel(keyLength))
          .macKeyKdf(kdf.toModel(keyLength))
          .pdkEncryptAlgorithm(aesGcm(keyLength))
          .build()
      )
      .build();
  }

  private static Encrypt aesGcm(int keyLength) {
    return Encrypt
      .builder()
      .AES_GCM(AES_GCM.builder().keyLength(keyLength).tagLength(TAG_LENGTH).ivLength(IV_LENGTH).build())
      .build();
  }

  /** Structural equality over the suite model classes, which define no equals. */
  private static final class Equality {

    private Equality() {}

    // Ignores id: the only caller looks up the expected suite by the candidate's id.
    static boolean same(AlgorithmSuiteInfo a, AlgorithmSuiteInfo b) {
      return (
        Arrays.equals(Buffers.toArray(a.binaryId()), Buffers.toArray(b.binaryId())) &&
        Objects.equals(a.messageVersion(), b.messageVersion()) &&
        same(a.encrypt(), b.encrypt()) &&
        same(a.kdf(), b.kdf()) &&
        same(a.commitment(), b.commitment()) &&
        same(a.signature(), b.signature()) &&
        same(a.symmetricSignature(), b.symmetricSignature()) &&
        same(a.edkWrapping(), b.edkWrapping())
      );
    }

    static boolean same(Encrypt a, Encrypt b) {
      return same(a.AES_GCM(), b.AES_GCM());
    }

    static boolean same(AES_GCM a, AES_GCM b) {
      return a.keyLength() == b.keyLength() && a.tagLength() == b.tagLength() && a.ivLength() == b.ivLength();
    }

    static boolean same(DerivationAlgorithm a, DerivationAlgorithm b) {
      if (a.HKDF() != null || b.HKDF() != null) {
        return a.HKDF() != null && b.HKDF() != null && same(a.HKDF(), b.HKDF());
      }
      return (a.IDENTITY() == null) == (b.IDENTITY() == null) && (a.None() == null) == (b.None() == null);
    }

    static boolean same(HKDF a, HKDF b) {
      return (
        a.hmac() == b.hmac() &&
        a.saltLength() == b.saltLength() &&
        a.inputKeyLength() == b.inputKeyLength() &&
        a.outputKeyLength() == b.outputKeyLength()
      );
    }

    static boolean same(SignatureAlgorithm a, SignatureAlgorithm b) {
      if (a.ECDSA() != null || b.ECDSA() != null) {
        return a.ECDSA() != null && b.ECDSA() != null && a.ECDSA().curve() == b.ECDSA().curve();
      }
      return true;
    }

    static boolean same(SymmetricSignatureAlgorithm a, SymmetricSignatureAlgorithm b) {
      return a.HMAC() == b.HMAC();
    }

    static boolean same(EdkWrappingAlgorithm a, EdkWrappingAlgorithm b) {
      IntermediateKeyWrapping x = a.IntermediateKeyWrapping();
      IntermediateKeyWrapping y = b.IntermediateKeyWrapping();
      if (x == null || y == null) {
        return x == y;
      }
      return (
        same(x.keyEncryptionKeyKdf(), y.keyEncryptionKeyKdf()) &&
        same(x.macKeyKdf(), y.macKeyKdf()) &&
        same(x.pdkEncryptAlgorithm(), y.pdkEncryptAlgorithm())
      );
    }
  }
}
