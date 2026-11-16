// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.oldapi.materialproviders.KmsKeyringTests.REGION;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.fakeaws.ServiceError;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.exceptions.AccessDeniedException;
import software.amazon.cryptography.materialproviders.exceptions.EncryptionContextMismatchException;
import software.amazon.cryptography.materialproviders.exceptions.MaterialProvidersException;
import software.amazon.cryptography.materialproviders.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.materialproviders.exceptions.ServiceException;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsEcdhKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsRsaKeyring;
import software.amazon.cryptography.materialproviders.keyrings.EcdhCurveSpec;
import software.amazon.cryptography.materialproviders.keyrings.KmsEcdhKeyAgreementScheme;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;

// What the new API adds over the old one for the KMS RSA and ECDH keyrings, which the differential tests cannot see:
// builder and configuration checks, copies, accessors, and error kinds with the SDK exception as cause.
class KmsAsymmetricKeyringsNativeApiTest {

  private static final AlgorithmSuite SUITE = EsdkAlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;

  private final FakeAws aws = FakeAws.start();
  private final KmsClient kms = aws.kmsClient("native", REGION);

  @AfterEach
  void close() {
    aws.close();
  }

  @Test
  void requiredArguments() {
    byte[] key = new byte[1];
    assertMessage(ValidationException.class, "Missing value for required field `kmsKeyId`", () -> AwsKmsRsaKeyring.builder().encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1).kmsClient(kms).build());
    assertMessage(ValidationException.class, "Missing value for required field `encryptionAlgorithm`", () -> AwsKmsRsaKeyring.builder().kmsKeyId("arn").kmsClient(kms).build());
    assertMessage(ValidationException.class, "Missing value for required field `senderKmsIdentifier`", () -> KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey(null, key));
    assertMessage(ValidationException.class, "Missing value for required field `recipientPublicKey`", () -> KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey("id", (byte[]) null));
    assertMessage(ValidationException.class, "Missing value for required field `senderKmsIdentifier`", () -> KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey(null, key, key));
    assertMessage(ValidationException.class, "Missing value for required field `senderPublicKey`", () -> KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey("id", null, key));
    assertMessage(ValidationException.class, "Missing value for required field `recipientPublicKey`", () -> KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey("id", key, null));
    assertMessage(ValidationException.class, "Missing value for required field `recipientKmsIdentifier`", () -> KmsEcdhKeyAgreementScheme.kmsPublicKeyDiscovery(null));
    KmsEcdhKeyAgreementScheme scheme = KmsEcdhKeyAgreementScheme.kmsPublicKeyDiscovery("id");
    assertMessage(ValidationException.class, "Missing value for required field `keyAgreementScheme`", () -> AwsKmsEcdhKeyring.builder().curveSpec(EcdhCurveSpec.ECC_NIST_P256).kmsClient(kms).build());
    assertMessage(ValidationException.class, "Missing value for required field `curveSpec`", () -> AwsKmsEcdhKeyring.builder().keyAgreementScheme(scheme).kmsClient(kms).build());
    assertMessage(ValidationException.class, "Missing value for required field `kmsClient`", () -> AwsKmsEcdhKeyring.builder().keyAgreementScheme(scheme).curveSpec(EcdhCurveSpec.ECC_NIST_P256).build());
  }

  @Test
  void rsaKeyringCopiesItsKeyAndHasAccessors() {
    String arn = aws.kms().createRsaKey(REGION, "RSA_2048");
    byte[] pem = aws.kms().publicKeyPem(arn).getBytes(StandardCharsets.UTF_8);
    byte[] callerCopy = pem.clone();
    List<String> tokens = Arrays.asList("t1", "t2");
    AwsKmsRsaKeyring keyring = AwsKmsRsaKeyring.builder().publicKey(callerCopy).kmsKeyId(arn).encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256).kmsClient(kms).grantTokens(tokens).build();
    Arrays.fill(callerCopy, (byte) 0);
    keyring.publicKey().get()[0] = 0;
    assertTrue(Arrays.equals(pem, keyring.publicKey().get()));
    assertEquals(arn, keyring.kmsKeyId());
    assertEquals(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256, keyring.encryptionAlgorithm());
    assertSame(kms, keyring.kmsClient().get());
    assertEquals(tokens, keyring.grantTokens());
    assertThrows(UnsupportedOperationException.class, () -> keyring.grantTokens().add("t3"));
    EncryptionMaterials encrypted = keyring.onEncrypt(OnEncryptRequest.builder().materials(start()).build()).materials();
    DecryptionMaterials decrypted = keyring.onDecrypt(OnDecryptRequest.builder().materials(decryptStart()).encryptedDataKeys(encrypted.encryptedDataKeys()).build()).materials();
    assertTrue(decrypted.plaintextDataKey().get().contentEquals(encrypted.plaintextDataKey().get()));

    AwsKmsRsaKeyring encryptOnly = AwsKmsRsaKeyring.builder().publicKey(pem).kmsKeyId(arn).encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1).build();
    assertFalse(encryptOnly.kmsClient().isPresent());
    assertEquals(Collections.emptyList(), encryptOnly.grantTokens());
    assertFalse(AwsKmsRsaKeyring.builder().kmsKeyId(arn).encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1).kmsClient(kms).build().publicKey().isPresent());
  }

  @Test
  void rsaKeyringErrorKinds() {
    String arn = aws.kms().createRsaKey(REGION, "RSA_2048");
    byte[] pem = aws.kms().publicKeyPem(arn).getBytes(StandardCharsets.UTF_8);
    AwsKmsRsaKeyring keyring = AwsKmsRsaKeyring.builder().publicKey(pem).kmsKeyId(arn).encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256).kmsClient(kms).build();
    EncryptionMaterials encrypted = keyring.onEncrypt(OnEncryptRequest.builder().materials(start()).build()).materials();
    assertMessage(ValidationException.class, "A publicKey or a kmsClient is required", () -> AwsKmsRsaKeyring.builder().kmsKeyId(arn).encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1).build());
    assertMessage(ValidationException.class, "Unsupported EncryptionAlgorithmSpec", () -> AwsKmsRsaKeyring.builder().kmsKeyId(arn).encryptionAlgorithm(EncryptionAlgorithmSpec.SM2_PKE).kmsClient(kms).build());

    aws.kms().fail("Decrypt", null, ServiceError.accessDenied("no"));
    NoMatchingDataKeyException failed = assertThrows(NoMatchingDataKeyException.class, () -> keyring.onDecrypt(OnDecryptRequest.builder().materials(decryptStart()).encryptedDataKeys(encrypted.encryptedDataKeys()).build()));
    assertTrue(failed.failures().get(0) instanceof AccessDeniedException);
    assertTrue(failed.failures().get(0).getCause() instanceof SdkException);
    aws.kms().clearFailures();

    aws.kms().editResponses("Decrypt", r -> r.put("KeyId", "other"));
    failed = assertThrows(NoMatchingDataKeyException.class, () -> keyring.onDecrypt(OnDecryptRequest.builder().materials(decryptStart()).encryptedDataKeys(encrypted.encryptedDataKeys()).build()));
    assertTrue(failed.failures().get(0) instanceof ServiceException);
    aws.kms().clearFailures();

    // A plaintext of the wrong length is a malformed response; the right length with another digest, another context.
    aws.kms().editResponses("Decrypt", r -> r.put("Plaintext", Base64.getEncoder().encodeToString(new byte[48])));
    failed = assertThrows(NoMatchingDataKeyException.class, () -> keyring.onDecrypt(OnDecryptRequest.builder().materials(decryptStart()).encryptedDataKeys(encrypted.encryptedDataKeys()).build()));
    assertTrue(failed.failures().get(0) instanceof ServiceException, failed.failures().toString());
    aws.kms().clearFailures();

    DecryptionMaterials otherContext = DecryptionMaterials.builder(SUITE).encryptionContext(EncryptionContext.of("a", "c")).build();
    failed = assertThrows(NoMatchingDataKeyException.class, () -> keyring.onDecrypt(OnDecryptRequest.builder().materials(otherContext).encryptedDataKeys(encrypted.encryptedDataKeys()).build()));
    assertTrue(failed.failures().get(0) instanceof EncryptionContextMismatchException, failed.failures().toString());
    assertTrue(assertThrows(NoMatchingDataKeyException.class, () -> keyring.onDecrypt(OnDecryptRequest.builder().materials(decryptStart()).encryptedDataKeys(Collections.emptyList()).build())).failures().isEmpty());
  }

  @Test
  void ecdhConfigurationsCopyKeysAndKeyringHasAccessors() {
    String sender = aws.kms().createEccKeyAgreementKey(REGION, "ECC_NIST_P256");
    String recipient = aws.kms().createEccKeyAgreementKey(REGION, "ECC_NIST_P256");
    byte[] senderKey = publicKey(sender);
    byte[] recipientKey = publicKey(recipient);
    KmsEcdhKeyAgreementScheme fetched = KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey(sender, recipientKey.clone());
    byte[] senderCopy = senderKey.clone();
    byte[] recipientCopy = recipientKey.clone();
    KmsEcdhKeyAgreementScheme supplied = KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey(sender, senderCopy, recipientCopy);
    Arrays.fill(senderCopy, (byte) 0);
    Arrays.fill(recipientCopy, (byte) 0);
    KmsEcdhKeyAgreementScheme discovery = KmsEcdhKeyAgreementScheme.kmsPublicKeyDiscovery(recipient);
    assertEquals(KmsEcdhKeyAgreementScheme.Kind.KMS_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY, fetched.kind());
    assertEquals(KmsEcdhKeyAgreementScheme.Kind.KMS_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY, supplied.kind());
    assertEquals(KmsEcdhKeyAgreementScheme.Kind.KMS_PUBLIC_KEY_DISCOVERY, discovery.kind());

    List<String> tokens = Collections.singletonList("t");
    AwsKmsEcdhKeyring discoveryKeyring = ecdh(discovery, tokens);
    assertSame(discovery, discoveryKeyring.keyAgreementScheme());
    assertEquals(EcdhCurveSpec.ECC_NIST_P256, discoveryKeyring.curveSpec());
    assertSame(kms, discoveryKeyring.kmsClient());
    assertEquals(tokens, discoveryKeyring.grantTokens());
    assertThrows(UnsupportedOperationException.class, () -> discoveryKeyring.grantTokens().add("u"));
    for (KmsEcdhKeyAgreementScheme scheme : Arrays.asList(fetched, supplied)) {
      AwsKmsEcdhKeyring keyring = ecdh(scheme, null);
      assertEquals(Collections.emptyList(), keyring.grantTokens());
      EncryptionMaterials encrypted = keyring.onEncrypt(OnEncryptRequest.builder().materials(start()).build()).materials();
      for (AwsKmsEcdhKeyring decryptor : Arrays.asList(keyring, discoveryKeyring)) {
        DecryptionMaterials decrypted = decryptor.onDecrypt(OnDecryptRequest.builder().materials(decryptStart()).encryptedDataKeys(encrypted.encryptedDataKeys()).build()).materials();
        assertTrue(decrypted.plaintextDataKey().get().contentEquals(encrypted.plaintextDataKey().get()));
      }
    }
  }

  @Test
  void ecdhKeyringErrorKinds() {
    String sender = aws.kms().createEccKeyAgreementKey(REGION, "ECC_NIST_P256");
    String recipient = aws.kms().createEccKeyAgreementKey(REGION, "ECC_NIST_P256");
    KmsEcdhKeyAgreementScheme discovery = KmsEcdhKeyAgreementScheme.kmsPublicKeyDiscovery(recipient);
    aws.kms().fail("GetPublicKey", null, ServiceError.accessDenied("no"));
    AccessDeniedException denied = assertThrows(AccessDeniedException.class, () -> ecdh(discovery, null));
    assertTrue(denied.getCause() instanceof SdkException);
    aws.kms().clearFailures();
    aws.kms().editResponses("GetPublicKey", r -> r.put("KeyUsage", "ENCRYPT_DECRYPT"));
    assertMessage(ServiceException.class, "Invalid response from KMS GetPublicKey", () -> ecdh(discovery, null));
    aws.kms().clearFailures();

    AwsKmsEcdhKeyring keyring = ecdh(KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey(sender, publicKey(recipient)), null);
    assertMessage(ValidationException.class, "KmsPublicKeyDiscovery Key Agreement Scheme is forbidden on encrypt.", () -> ecdh(discovery, null).onEncrypt(OnEncryptRequest.builder().materials(start()).build()));
    aws.kms().editResponses("DeriveSharedSecret", r -> {
      r.remove("KeyAgreementAlgorithm");
      return r;
    });
    assertMessage(ServiceException.class, "Invalid response from KMS DeriveSharedSecret", () -> keyring.onEncrypt(OnEncryptRequest.builder().materials(start()).build()));
    aws.kms().clearFailures();
    aws.kms().editResponses("DeriveSharedSecret", r -> r.put("SharedSecret", Base64.getEncoder().encodeToString(new byte[31])));
    assertMessage(ServiceException.class, "Kdf in Counter Mode input is invalid.", () -> keyring.onEncrypt(OnEncryptRequest.builder().materials(start()).build()));
    aws.kms().clearFailures();
    aws.kms().fail("DeriveSharedSecret", null, ServiceError.throttling("slow"));
    MaterialProvidersException throttled = assertThrows(MaterialProvidersException.class, () -> keyring.onEncrypt(OnEncryptRequest.builder().materials(start()).build()));
    assertTrue(throttled.isRetryable());
    assertTrue(throttled.getCause() instanceof SdkException);
    aws.kms().clearFailures();
  }

  private AwsKmsEcdhKeyring ecdh(KmsEcdhKeyAgreementScheme scheme, List<String> grantTokens) {
    return AwsKmsEcdhKeyring.builder().keyAgreementScheme(scheme).curveSpec(EcdhCurveSpec.ECC_NIST_P256).kmsClient(kms).grantTokens(grantTokens).build();
  }

  private byte[] publicKey(String arn) {
    return Base64.getMimeDecoder().decode(aws.kms().publicKeyPem(arn).replaceAll("-----[A-Z ]*-----", ""));
  }

  private static EncryptionMaterials start() {
    return EncryptionMaterials.builder(SUITE).encryptionContext(EncryptionContext.of("a", "b")).build();
  }

  private static DecryptionMaterials decryptStart() {
    return DecryptionMaterials.builder(SUITE).encryptionContext(EncryptionContext.of("a", "b")).build();
  }

  private static void assertMessage(Class<? extends RuntimeException> kind, String message, Executable call) {
    RuntimeException e = assertThrows(kind, call);
    assertEquals(message, e.getMessage());
    assertNull(kind == ValidationException.class ? e.getCause() : null);
  }
}
