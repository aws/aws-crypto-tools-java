// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

// Each format's enum holds its own suites, finds only its own ids, and the materials and requests accept only the two enums.
class AlgorithmSuiteSplitTest {

  @Test
  void eachEnumHoldsItsFormat() {
    assertEquals(11, EsdkAlgorithmSuite.values().length);
    assertEquals(2, DbeAlgorithmSuite.values().length);
    for (EsdkAlgorithmSuite suite : EsdkAlgorithmSuite.values()) {
      assertEquals(AlgorithmSuite.Format.ESDK, suite.format(), suite.name());
      assertFalse(suite.isSymmetricSigning(), suite.name());
      assertFalse(suite.usesIntermediateKeyWrapping(), suite.name());
    }
    for (DbeAlgorithmSuite suite : DbeAlgorithmSuite.values()) {
      assertEquals(AlgorithmSuite.Format.DBE, suite.format(), suite.name());
      assertTrue(suite.isSymmetricSigning(), suite.name());
      assertTrue(suite.usesIntermediateKeyWrapping(), suite.name());
    }
  }

  @Test
  void eachLookupFindsOnlyItsFormat() {
    for (EsdkAlgorithmSuite suite : EsdkAlgorithmSuite.values()) {
      assertSame(suite, EsdkAlgorithmSuite.fromBinaryId(suite.binaryId()));
      assertMessage("Invalid BinaryId", () -> DbeAlgorithmSuite.fromBinaryId(suite.binaryId()));
    }
    for (DbeAlgorithmSuite suite : DbeAlgorithmSuite.values()) {
      assertSame(suite, DbeAlgorithmSuite.fromBinaryId(suite.binaryId()));
      assertMessage("Invalid BinaryId", () -> EsdkAlgorithmSuite.fromBinaryId(suite.binaryId()));
    }
    assertMessage("Invalid BinaryId", () -> EsdkAlgorithmSuite.fromBinaryId(new byte[] { 0x04 }));
    assertMessage("Invalid BinaryId", () -> DbeAlgorithmSuite.fromBinaryId(new byte[] { 0x67, 0x00, 0x00 }));
  }

  @Test
  void defaultSuitesHaveThePolicysFormat() {
    EsdkAlgorithmSuite esdk = EsdkCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT.defaultSuite();
    DbeAlgorithmSuite dbe = DbeCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT.defaultSuite();
    assertSame(EsdkAlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, esdk);
    assertSame(EsdkAlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, EsdkCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT.defaultSuite());
    assertSame(DbeAlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384, dbe);
  }

  @Test
  void otherImplementationsAreRejected() {
    AlgorithmSuite foreign = new Foreign();
    String message = "Algorithm suite must be an EsdkAlgorithmSuite or a DbeAlgorithmSuite";
    assertMessage(message, () -> EncryptionMaterials.builder(foreign));
    assertMessage(message, () -> DecryptionMaterials.builder(foreign));
    assertMessage(
      message,
      () -> GetEncryptionMaterialsRequest
        .builder()
        .encryptionContext(EncryptionContext.empty())
        .commitmentPolicy(EsdkCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
        .algorithmSuite(foreign)
        .build()
    );
    assertMessage(
      message,
      () -> DecryptMaterialsRequest
        .builder()
        .algorithmSuite(foreign)
        .commitmentPolicy(EsdkCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
        .encryptedDataKeys()
        .encryptionContext(EncryptionContext.empty())
        .build()
    );
  }

  private static void assertMessage(String message, Runnable call) {
    assertEquals(message, assertThrows(ValidationException.class, call::run).getMessage());
  }

  // Claims to be the committing ESDK suite.
  private static final class Foreign implements AlgorithmSuite {

    @Override
    public String name() {
      return "ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY";
    }

    @Override
    public Format format() {
      return Format.ESDK;
    }

    @Override
    public byte[] binaryId() {
      return new byte[] { 0x04, 0x78 };
    }

    @Override
    public int messageVersion() {
      return 2;
    }

    @Override
    public int dataKeyLength() {
      return 32;
    }

    @Override
    public KeyDerivation keyDerivation() {
      return KeyDerivation.HKDF_SHA512;
    }

    @Override
    public boolean isCommitting() {
      return true;
    }

    @Override
    public Optional<Signature> signature() {
      return Optional.empty();
    }

    @Override
    public boolean isSymmetricSigning() {
      return false;
    }
  }
}
