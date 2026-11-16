// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk.integration;

import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;

/**
 * The ESDK's {@code com.amazonaws.encryptionsdk.CryptoAlgorithm}, rebuilt on the native suite catalogue.
 *
 * <p>ESDK 3.x builds a {@code MaterialProviders} client for each constant and calls {@code GetAlgorithmSuiteInfo}
 * while the enum initializes. Here each constant looks its {@link EsdkAlgorithmSuite} up by id, with no client.
 * The getters that read MPL suite facts keep their ESDK names and return what ESDK 3.x returns. Getters that do not
 * depend on the MPL ({@code getBlockSize}, {@code getMaxContentLen}, {@code getKeyAlgo}, key derivation) are left out;
 * {@link #getKdfMacAlgo} is not in the ESDK and serves the stand-in's key derivation.
 */
public enum CryptoAlgorithm {
  ALG_AES_128_GCM_IV12_TAG16_NO_KDF(0x0014),
  ALG_AES_192_GCM_IV12_TAG16_NO_KDF(0x0046),
  ALG_AES_256_GCM_IV12_TAG16_NO_KDF(0x0078),
  ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256(0x0114),
  ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256(0x0146),
  ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256(0x0178),
  ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256(0x0214),
  ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384(0x0346),
  ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384(0x0378),
  ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY(0x0478),
  ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384(0x0578);

  private final short value;
  private final EsdkAlgorithmSuite suite;

  CryptoAlgorithm(int value) {
    this.value = (short) value;
    this.suite = EsdkAlgorithmSuite.fromBinaryId(value);
  }

  /** Replaces {@code getAlgorithmSuiteId()}, which returned the MPL's {@code AlgorithmSuiteId} union. */
  public EsdkAlgorithmSuite algorithmSuite() {
    return suite;
  }

  /**
   * The constant for a suite the MPL returned. Replaces {@code CryptoAlgorithm.valueOf(suite.id().ESDK().name())}.
   * The constant names are the same in both enums.
   *
   * @throws IllegalArgumentException for a DBE suite (ESDK 3.x threw NullPointerException there)
   */
  public static CryptoAlgorithm of(AlgorithmSuite suite) {
    return valueOf(suite.name());
  }

  /** The suite for a message header's version and id, or null, as in ESDK 3.x. */
  public static CryptoAlgorithm deserialize(byte messageFormatVersion, short value) {
    for (CryptoAlgorithm algorithm : values()) {
      if (algorithm.value == value && algorithm.getMessageFormatVersion() == messageFormatVersion) {
        return algorithm;
      }
    }
    return null;
  }

  public short getValue() {
    return value;
  }

  public byte getMessageFormatVersion() {
    return (byte) suite.messageVersion();
  }

  public int getMessageIdLength() {
    switch (suite.messageVersion()) {
      case 1:
        return 16;
      case 2:
        return 32;
      default:
        throw new UnsupportedOperationException("Support for version " + suite.messageVersion() + " not yet built.");
    }
  }

  /** Null for version 1, where the header IV is in the message; version 2 uses an all-zero IV. */
  public byte[] getHeaderNonce() {
    return suite.messageVersion() == 1 ? null : new byte[suite.ivLength()];
  }

  public byte getNonceLen() {
    return (byte) suite.ivLength();
  }

  public int getTagLen() {
    return suite.tagLength();
  }

  public int getKeyLength() {
    return suite.dataKeyLength();
  }

  public int getDataKeyLength() {
    return suite.dataKeyLength();
  }

  /** The ESDK's own JCA names for the data key ("AES" or "HkdfSHA..."), which the ESDK's key derivation expects. */
  public String getDataKeyAlgo() {
    switch (suite.keyDerivation()) {
      case IDENTITY:
        return "AES";
      case HKDF_SHA256:
        return "HkdfSHA256";
      case HKDF_SHA384:
        return "HkdfSHA384";
      case HKDF_SHA512:
        return "HkdfSHA512";
      default:
        throw new UnsupportedOperationException("Support for Data Key Algorithm:" + suite.keyDerivation() + " not yet built");
    }
  }

  /** The JCA {@code Mac} name of the key derivation's hash; null without key derivation. */
  public String getKdfMacAlgo() {
    return suite.keyDerivation().hmacAlgorithm().orElse(null);
  }

  /** The JCA {@code Signature} name; null for a suite that does not sign. */
  public String getTrailingSignatureAlgo() {
    return suite.signature().map(AlgorithmSuite.Signature::jcaAlgorithm).orElse(null);
  }

  /** The longest DER-encoded signature; the ESDK pads to it. */
  public short getTrailingSignatureLength() {
    if (!suite.signature().isPresent()) {
      return 0;
    }
    switch (suite.signature().get()) {
      case ECDSA_P256:
        return 71;
      case ECDSA_P384:
        return 103;
      default:
        throw new UnsupportedOperationException("Support for Data Key Algorithm:" + suite.signature().get() + " not yet built");
    }
  }

  public boolean isSafeToCache() {
    return suite.keyDerivation() != AlgorithmSuite.KeyDerivation.IDENTITY;
  }

  public boolean isCommitting() {
    return suite.isCommitting();
  }

  /** The ESDK's own JCA name of the commitment HKDF; the HMAC under it is {@code suite.commitmentHmacAlgorithm()}. */
  public String getKeyCommitmentAlgo_() {
    return suite.isCommitting() ? "HkdfSHA512" : null;
  }

  /** ESDK 3.x: {@code commitment().HKDF().inputKeyLength()}. */
  public int getCommitmentLength() {
    return suite.commitmentKeyLength();
  }

  /** ESDK 3.x: {@code commitment().HKDF().saltLength()}, the same value as the KDF salt length. */
  public int getCommitmentNonceLength() {
    return suite.kdfSaltLength();
  }

  /** ESDK 3.x: {@code commitment().HKDF().outputKeyLength()}. */
  public int getSuiteDataLength() {
    return suite.commitmentKeyLength();
  }
}
