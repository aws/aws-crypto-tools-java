// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.mpl.cmm.DefaultCryptographicMaterialsManager;
import software.amazon.cryptography.mpl.exceptions.CryptographicException;
import software.amazon.cryptography.mpl.exceptions.EncryptionContextMismatchException;
import software.amazon.cryptography.mpl.exceptions.ErrorKind;
import software.amazon.cryptography.mpl.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.primitives.EcKeys;
import software.amazon.cryptography.mpl.internal.primitives.RsaKeyGeneration;
import software.amazon.cryptography.mpl.keyrings.PaddingScheme;
import software.amazon.cryptography.mpl.keyrings.RawRsaKeyring;

// Native API behavior the old-API differential tests cannot see: error kinds, documented orders, and defensive copies.
class NativeApiTest {

  private static final byte[][] RSA = RsaKeyGeneration.generateKeyPair(2048);

  @Test
  void aTamperedRsaKeyIsACryptographicFailure() {
    RawRsaKeyring keyring = rsa(RSA[0].clone(), RSA[1].clone());
    EncryptionMaterials encrypted = keyring.onEncrypt(OnEncryptRequest.builder().materials(EncryptionMaterials.builder(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).build()).build()).materials();
    EncryptedDataKey edk = encrypted.encryptedDataKeys().get(0);
    byte[] ciphertext = edk.ciphertext();
    ciphertext[5] ^= 1;
    NoMatchingDataKeyException e = assertThrows(
      NoMatchingDataKeyException.class,
      () -> keyring.onDecrypt(OnDecryptRequest.builder().materials(decryption()).encryptedDataKeys(Collections.singletonList(EncryptedDataKey.of(edk.keyProviderId(), edk.keyProviderInfo(), ciphertext))).build())
    );
    assertInstanceOf(CryptographicException.class, e.failures().get(0));
  }

  @Test
  void anUnparsableRsaKeyIsAValidationFailure() {
    RawRsaKeyring keyring = rsa("not a key".getBytes(java.nio.charset.StandardCharsets.US_ASCII), null);
    assertThrows(
      ValidationException.class,
      () -> keyring.onEncrypt(OnEncryptRequest.builder().materials(EncryptionMaterials.builder(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).build()).build())
    );
  }

  @Test
  void anEmptyVerificationKeyIsAValidationFailure() {
    ValidationException e = assertThrows(
      ValidationException.class,
      () -> EcKeys.publicKey(AlgorithmSuite.Signature.ECDSA_P384, new byte[0])
    );
    assertEquals(EcKeys.EMPTY_VERIFICATION_KEY, e.getMessage());
    assertThrows(ValidationException.class, () -> EcKeys.privateKey(AlgorithmSuite.Signature.ECDSA_P384, new byte[0]));
  }

  @Test
  void theRsaKeyringKeepsItsOwnCopiesOfTheKeys() {
    byte[] publicKey = RSA[0].clone();
    SecretBytes privateKey = SecretBytes.copyOf(RSA[1]);
    RawRsaKeyring keyring = rsa(publicKey, privateKey);
    Arrays.fill(publicKey, (byte) 0);
    privateKey.destroy();
    EncryptionMaterials encrypted = keyring.onEncrypt(OnEncryptRequest.builder().materials(EncryptionMaterials.builder(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).build()).build()).materials();
    DecryptionMaterials decrypted = keyring.onDecrypt(OnDecryptRequest.builder().materials(decryption()).encryptedDataKeys(encrypted.encryptedDataKeys()).build()).materials();
    assertArrayEquals(encrypted.plaintextDataKey().get().toByteArray(), decrypted.plaintextDataKey().get().toByteArray());
  }

  // Keys only in the reproduced context become required keys in UTF-8 byte order.
  @Test
  void reproducedOnlyKeysAreRequiredInByteOrder() {
    RawRsaKeyring keyring = rsa(RSA[0].clone(), RSA[1].clone());
    DefaultCryptographicMaterialsManager cmm = DefaultCryptographicMaterialsManager.of(keyring);
    EncryptionContext context = EncryptionContext.of("d", "4", "b", "2", "c", "3", "\u00e9", "5");
    EncryptionMaterials encrypted = cmm.getEncryptionMaterials(
      GetEncryptionMaterialsRequest.builder().encryptionContext(context).commitmentPolicy(EsdkCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .algorithmSuiteId(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).build()
    ).encryptionMaterials();
    DecryptionMaterials decrypted = cmm.decryptMaterials(
      DecryptMaterialsRequest
        .builder()
        .algorithmSuiteId(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
        .commitmentPolicy(EsdkCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .encryptedDataKeys(encrypted.encryptedDataKeys())
        .encryptionContext(EncryptionContext.empty())
        .reproducedEncryptionContext(context)
        .build()
    ).decryptionMaterials();
    List<String> expected = Arrays.asList("b", "c", "d", "\u00e9");
    assertEquals(expected, decrypted.requiredEncryptionContextKeys());
  }

  // An edited or moved item (DB-ESDK) or a wrong context (ESDK) is its own kind, apart from configuration errors.
  @Test
  void aReproducedValueThatDiffersIsAContextMismatch() {
    DefaultCryptographicMaterialsManager cmm = DefaultCryptographicMaterialsManager.of(rsa(RSA[0].clone(), RSA[1].clone()));
    CryptographicMaterialsManager required = software.amazon.cryptography.mpl.cmm.RequiredEncryptionContextCryptographicMaterialsManager
      .builder()
      .underlyingCmm(cmm)
      .requiredEncryptionContextKeys(Collections.singletonList("r"))
      .build();
    EncryptionMaterials encrypted = cmm.getEncryptionMaterials(
      GetEncryptionMaterialsRequest.builder().encryptionContext(EncryptionContext.of("a", "1")).commitmentPolicy(EsdkCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .algorithmSuiteId(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).build()
    ).encryptionMaterials();
    DecryptMaterialsRequest request = DecryptMaterialsRequest
      .builder()
      .algorithmSuiteId(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
      .commitmentPolicy(EsdkCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
      .encryptedDataKeys(encrypted.encryptedDataKeys())
      .encryptionContext(EncryptionContext.of("a", "1"))
      .reproducedEncryptionContext(EncryptionContext.of("a", "2", "r", "x"))
      .build();
    for (CryptographicMaterialsManager manager : Arrays.asList(cmm, required)) {
      EncryptionContextMismatchException e = assertThrows(EncryptionContextMismatchException.class, () -> manager.decryptMaterials(request));
      assertEquals("Encryption context does not match reproduced encryption context.", e.getMessage());
      assertEquals(ErrorKind.ENCRYPTION_CONTEXT_MISMATCH, e.kind());
    }
    // A missing required key stays a validation failure.
    DecryptMaterialsRequest missing = request.toBuilder().reproducedEncryptionContext(EncryptionContext.of("a", "1")).build();
    assertEquals("Reproduced encryption context missing required keys.", assertThrows(ValidationException.class, () -> required.decryptMaterials(missing)).getMessage());
  }

  private static RawRsaKeyring rsa(byte[] publicKey, Object privateKey) {
    RawRsaKeyring.Builder builder = RawRsaKeyring.builder().keyNamespace("ns").keyName("name").paddingScheme(PaddingScheme.OAEP_SHA256_MGF1);
    if (publicKey != null) {
      builder.publicKey(publicKey);
    }
    if (privateKey instanceof byte[]) {
      builder.privateKey(SecretBytes.copyOf((byte[]) privateKey));
    } else if (privateKey instanceof SecretBytes) {
      builder.privateKey((SecretBytes) privateKey);
    }
    return builder.build();
  }

  private static DecryptionMaterials decryption() {
    return DecryptionMaterials.builder(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).build();
  }
}
