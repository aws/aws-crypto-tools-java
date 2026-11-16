// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders.internal;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import software.amazon.cryptography.materialproviders.DbeCommitmentPolicy;
import software.amazon.cryptography.materialproviders.EsdkCommitmentPolicy;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.internal.MaterialsRules;
import software.amazon.cryptography.oldapi.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.AlgorithmSuiteInfo;
import software.amazon.cryptography.oldapi.materialproviders.model.CommitmentPolicy;
import software.amazon.cryptography.oldapi.materialproviders.model.DBEAlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.DIRECT_KEY_WRAPPING;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.DerivationAlgorithm;
import software.amazon.cryptography.oldapi.materialproviders.model.ECDSA;
import software.amazon.cryptography.oldapi.materialproviders.model.ESDKAlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.EdkWrappingAlgorithm;
import software.amazon.cryptography.oldapi.materialproviders.model.Encrypt;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.HKDF;
import software.amazon.cryptography.oldapi.materialproviders.model.IntermediateKeyWrapping;
import software.amazon.cryptography.oldapi.materialproviders.model.None;
import software.amazon.cryptography.oldapi.materialproviders.model.SignatureAlgorithm;
import software.amazon.cryptography.oldapi.materialproviders.model.SymmetricSignatureAlgorithm;
import software.amazon.cryptography.oldapi.primitives.model.AES_GCM;
import software.amazon.cryptography.oldapi.primitives.model.DigestAlgorithm;
import software.amazon.cryptography.oldapi.primitives.model.ECDSASignatureAlgorithm;

/**
 * Test adapter: converts between the old-shape model (the Dafny-based MPL's Java API, kept in test sources)
 * and the native core, so the differential tests drive the core through the old API.
 */
public final class Convert {

  private Convert() {}

  public static software.amazon.cryptography.materialproviders.AlgorithmSuite suite(AlgorithmSuiteId id) {
    String name = id.ESDK() != null ? id.ESDK().name() : id.DBE().name();
    return software.amazon.cryptography.materialproviders.AlgorithmSuite.valueOf(name);
  }

  public static AlgorithmSuiteId id(software.amazon.cryptography.materialproviders.AlgorithmSuite suite) {
    return suite.format() == software.amazon.cryptography.materialproviders.AlgorithmSuite.Format.ESDK
      ? AlgorithmSuiteId.builder().ESDK(ESDKAlgorithmSuiteId.valueOf(suite.name())).build()
      : AlgorithmSuiteId.builder().DBE(DBEAlgorithmSuiteId.valueOf(suite.name())).build();
  }

  public static software.amazon.cryptography.materialproviders.CommitmentPolicy policy(CommitmentPolicy policy) {
    return policy.ESDK() != null
      ? EsdkCommitmentPolicy.valueOf(policy.ESDK().name())
      : DbeCommitmentPolicy.valueOf(policy.DBE().name());
  }

  /** The old-shape suite description, built only from the native enum's accessors. */
  public static AlgorithmSuiteInfo info(software.amazon.cryptography.materialproviders.AlgorithmSuite suite) {
    DerivationAlgorithm kdf = kdf(suite);
    return AlgorithmSuiteInfo
      .builder()
      .id(id(suite))
      .binaryId(ByteBuffer.wrap(suite.binaryId()))
      .messageVersion(suite.messageVersion())
      .encrypt(aesGcm(suite.dataKeyLength(), suite.tagLength(), suite.ivLength()))
      .kdf(kdf)
      .commitment(suite.isCommitting() ? kdf : DerivationAlgorithm.builder().None(None.builder().build()).build())
      .signature(
        suite.signature().isPresent()
          ? SignatureAlgorithm
            .builder()
            .ECDSA(ECDSA.builder().curve(ECDSASignatureAlgorithm.valueOf(suite.signature().get().name())).build())
            .build()
          : SignatureAlgorithm.builder().None(None.builder().build()).build()
      )
      .symmetricSignature(
        suite.isSymmetricSigning()
          ? SymmetricSignatureAlgorithm.builder().HMAC(DigestAlgorithm.SHA_384).build()
          : SymmetricSignatureAlgorithm.builder().None(None.builder().build()).build()
      )
      .edkWrapping(
        suite.usesIntermediateKeyWrapping()
          ? EdkWrappingAlgorithm
            .builder()
            .IntermediateKeyWrapping(
              IntermediateKeyWrapping
                .builder()
                .keyEncryptionKeyKdf(kdf)
                .macKeyKdf(kdf)
                .pdkEncryptAlgorithm(aesGcm(suite.dataKeyLength(), suite.tagLength(), suite.ivLength()))
                .build()
            )
            .build()
          : EdkWrappingAlgorithm.builder().DIRECT_KEY_WRAPPING(DIRECT_KEY_WRAPPING.builder().build()).build()
      )
      .build();
  }

  private static DerivationAlgorithm kdf(software.amazon.cryptography.materialproviders.AlgorithmSuite suite) {
    if (suite.keyDerivation() == software.amazon.cryptography.materialproviders.AlgorithmSuite.KeyDerivation.IDENTITY) {
      return DerivationAlgorithm.builder().IDENTITY(software.amazon.cryptography.oldapi.materialproviders.model.IDENTITY.builder().build()).build();
    }
    DigestAlgorithm hmac = DigestAlgorithm.valueOf(suite.keyDerivation().name().substring("HKDF_".length()).replace("SHA", "SHA_"));
    return DerivationAlgorithm
      .builder()
      .HKDF(
        HKDF
          .builder()
          .hmac(hmac)
          .saltLength(suite.kdfSaltLength())
          .inputKeyLength(suite.dataKeyLength())
          .outputKeyLength(suite.dataKeyLength())
          .build()
      )
      .build();
  }

  private static Encrypt aesGcm(int keyLength, int tagLength, int ivLength) {
    return Encrypt.builder().AES_GCM(AES_GCM.builder().keyLength(keyLength).tagLength(tagLength).ivLength(ivLength).build()).build();
  }

  public static software.amazon.cryptography.materialproviders.EncryptedDataKey edk(EncryptedDataKey edk) {
    return software.amazon.cryptography.materialproviders.EncryptedDataKey.builder()
        .keyProviderId(edk.keyProviderId())
        .keyProviderInfo(Buffers.toArray(edk.keyProviderInfo()))
        .ciphertext(Buffers.toArray(edk.ciphertext()))
        .build();
  }

  public static EncryptedDataKey edk(software.amazon.cryptography.materialproviders.EncryptedDataKey edk) {
    return EncryptedDataKey
      .builder()
      .keyProviderId(edk.keyProviderId())
      .keyProviderInfo(ByteBuffer.wrap(edk.keyProviderInfo()))
      .ciphertext(ByteBuffer.wrap(edk.ciphertext()))
      .build();
  }

  /** Raw fields of old-shape materials whose suite description is valid. */
  public static MaterialsRules.Encryption fields(EncryptionMaterials m) {
    List<software.amazon.cryptography.materialproviders.EncryptedDataKey> edks = new ArrayList<>();
    for (EncryptedDataKey edk : m.encryptedDataKeys()) {
      edks.add(edk(edk));
    }
    List<SecretBytes> symmetric = new ArrayList<>();
    if (m.symmetricSigningKeys() != null) {
      for (ByteBuffer key : m.symmetricSigningKeys()) {
        symmetric.add(SecretBytes.copyOf(Buffers.toArray(key)));
      }
    }
    return new MaterialsRules.Encryption(
      suite(m.algorithmSuite().id()),
      new HashMap<>(m.encryptionContext()),
      edks,
      new ArrayList<>(m.requiredEncryptionContextKeys()),
      secret(m.plaintextDataKey()),
      secret(m.signingKey()),
      symmetric
    );
  }

  public static MaterialsRules.Decryption fields(DecryptionMaterials m) {
    return new MaterialsRules.Decryption(
      suite(m.algorithmSuite().id()),
      new HashMap<>(m.encryptionContext()),
      new ArrayList<>(m.requiredEncryptionContextKeys()),
      secret(m.plaintextDataKey()),
      m.verificationKey() == null ? null : Buffers.toArray(m.verificationKey()),
      secret(m.symmetricSigningKey())
    );
  }

  public static EncryptionMaterials materials(software.amazon.cryptography.materialproviders.EncryptionMaterials m) {
    List<EncryptedDataKey> edks = new ArrayList<>();
    for (software.amazon.cryptography.materialproviders.EncryptedDataKey edk : m.encryptedDataKeys()) {
      edks.add(edk(edk));
    }
    List<ByteBuffer> symmetric = null;
    if (m.algorithmSuite().isSymmetricSigning()) {
      symmetric = new ArrayList<>();
      for (SecretBytes key : m.symmetricSigningKeys()) {
        symmetric.add(ByteBuffer.wrap(key.toByteArray()));
      }
    }
    return EncryptionMaterials
      .builder()
      .algorithmSuite(info(m.algorithmSuite()))
      .encryptionContext(new HashMap<>(m.encryptionContext()))
      .encryptedDataKeys(edks)
      .requiredEncryptionContextKeys(new ArrayList<>(m.requiredEncryptionContextKeys()))
      .plaintextDataKey(m.plaintextDataKey().map(k -> ByteBuffer.wrap(k.toByteArray())).orElse(null))
      .signingKey(m.signingKey().map(k -> ByteBuffer.wrap(k.toByteArray())).orElse(null))
      .symmetricSigningKeys(symmetric)
      .build();
  }

  public static DecryptionMaterials materials(software.amazon.cryptography.materialproviders.DecryptionMaterials m) {
    return DecryptionMaterials
      .builder()
      .algorithmSuite(info(m.algorithmSuite()))
      .encryptionContext(new HashMap<>(m.encryptionContext()))
      .requiredEncryptionContextKeys(new ArrayList<>(m.requiredEncryptionContextKeys()))
      .plaintextDataKey(m.plaintextDataKey().map(k -> ByteBuffer.wrap(k.toByteArray())).orElse(null))
      .verificationKey(m.verificationKey().map(ByteBuffer::wrap).orElse(null))
      .symmetricSigningKey(m.symmetricSigningKey().map(k -> ByteBuffer.wrap(k.toByteArray())).orElse(null))
      .build();
  }

  private static SecretBytes secret(ByteBuffer buffer) {
    return buffer == null ? null : SecretBytes.copyOf(Buffers.toArray(buffer));
  }
}
