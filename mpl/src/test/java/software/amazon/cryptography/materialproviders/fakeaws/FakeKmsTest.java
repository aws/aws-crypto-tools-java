// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.fakeaws;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyWithoutPlaintextResponse;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.IncorrectKeyException;
import software.amazon.awssdk.services.kms.model.InvalidCiphertextException;
import software.amazon.awssdk.services.kms.model.InvalidKeyUsageException;
import software.amazon.awssdk.services.kms.model.KeyAgreementAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.NotFoundException;
import software.amazon.awssdk.services.kms.model.ReEncryptResponse;
import software.amazon.awssdk.services.kms.model.UnsupportedOperationException;

// The fake KMS through this module's AWS SDK. ReferenceAwsTest covers the reference MPL's SDK copy.
class FakeKmsTest {

  private static final String WEST = "us-west-2";
  private static final String EAST = "us-east-1";

  private final FakeAws aws = FakeAws.start();
  private final KmsClient west = aws.kmsClient("west", WEST);
  private final KmsClient east = aws.kmsClient("east", EAST);
  private final Map<String, String> context = context("purpose", "test", "a", "1");

  @AfterEach
  void close() {
    aws.close();
  }

  @Test
  void encryptDecryptRoundTrip() {
    String key = aws.kms().createSymmetricKey(WEST);
    EncryptResponse encrypted = west.encrypt(r -> r.keyId(key).plaintext(sdk(1, 2, 3)).encryptionContext(context));
    assertEquals(key, encrypted.keyId());
    assertEquals(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT, encrypted.encryptionAlgorithm());

    // With the key named, and without: the blob names its key.
    for (String keyId : Arrays.asList(key, null)) {
      DecryptResponse decrypted = west.decrypt(r ->
        r.keyId(keyId).ciphertextBlob(encrypted.ciphertextBlob()).encryptionContext(context)
      );
      assertEquals(key, decrypted.keyId());
      assertArrayEquals(bytes(1, 2, 3), decrypted.plaintext().asByteArray());
    }
  }

  @Test
  void generateDataKey() {
    String key = aws.kms().createSymmetricKey(WEST);
    GenerateDataKeyResponse generated = west.generateDataKey(r -> r.keyId(key).numberOfBytes(24).encryptionContext(context));
    assertEquals(key, generated.keyId());
    assertEquals(24, generated.plaintext().asByteArray().length);
    assertNull(generated.ciphertextForRecipient());
    assertArrayEquals(generated.plaintext().asByteArray(), decrypt(west, generated.ciphertextBlob(), context));

    assertEquals(32, west.generateDataKey(r -> r.keyId(key).keySpec("AES_256")).plaintext().asByteArray().length);
    assertEquals(16, west.generateDataKey(r -> r.keyId(key).keySpec("AES_128")).plaintext().asByteArray().length);
    assertEquals("ValidationException", errorCode(() -> west.generateDataKey(r -> r.keyId(key))));
    assertEquals("ValidationException", errorCode(() -> west.generateDataKey(r -> r.keyId(key).numberOfBytes(1025))));

    GenerateDataKeyWithoutPlaintextResponse withoutPlaintext = west.generateDataKeyWithoutPlaintext(r ->
      r.keyId(key).numberOfBytes(32).encryptionContext(context)
    );
    assertEquals(key, withoutPlaintext.keyId());
    assertEquals(32, decrypt(west, withoutPlaintext.ciphertextBlob(), context).length);
  }

  @Test
  void encryptionContextIsBound() {
    String key = aws.kms().createSymmetricKey(WEST);
    SdkBytes blob = west.encrypt(r -> r.keyId(key).plaintext(sdk(9)).encryptionContext(context)).ciphertextBlob();
    List<Map<String, String>> wrong = Arrays.asList(
      Collections.emptyMap(),
      context("purpose", "test"),
      context("purpose", "test", "a", "2"),
      context("purpose", "test", "a", "1", "b", "1"),
      context("purpose", "test", "a1", ""),
      context("purpose", "test", "b", "1")
    );
    for (Map<String, String> other : wrong) {
      assertThrows(InvalidCiphertextException.class, () -> decrypt(west, blob, other), other.toString());
    }
    // Absent and empty encryption context are the same.
    SdkBytes noContext = west.encrypt(r -> r.keyId(key).plaintext(sdk(9))).ciphertextBlob();
    assertArrayEquals(bytes(9), decrypt(west, noContext, Collections.emptyMap()));
  }

  @Test
  void changedBlobFails() {
    String key = aws.kms().createSymmetricKey(WEST);
    byte[] blob = west.encrypt(r -> r.keyId(key).plaintext(sdk(9)).encryptionContext(context)).ciphertextBlob().asByteArray();
    int ivStart = 3 + key.length();
    // Version, IV, ciphertext, and tag bytes.
    for (int index : new int[] { 0, ivStart, ivStart + 11, ivStart + 12, blob.length - 1 }) {
      byte[] changed = blob.clone();
      changed[index] ^= 1;
      assertThrows(InvalidCiphertextException.class, () -> decrypt(west, SdkBytes.fromByteArray(changed), context), "byte " + index);
    }
    // An ARN byte: the blob now names a key that does not exist, which KMS reports as access denied.
    byte[] otherKey = blob.clone();
    otherKey[ivStart - 1] ^= 1;
    assertEquals("AccessDeniedException", errorCode(() -> decrypt(west, SdkBytes.fromByteArray(otherKey), context)));
    assertThrows(InvalidCiphertextException.class, () -> decrypt(west, SdkBytes.fromByteArray(Arrays.copyOf(blob, blob.length - 17)), context));
    assertThrows(InvalidCiphertextException.class, () -> decrypt(west, SdkBytes.fromByteArray(bytes(1)), context));
  }

  @Test
  void decryptWithAnotherKeyFails() {
    String key = aws.kms().createSymmetricKey(WEST);
    String other = aws.kms().createSymmetricKey(WEST);
    SdkBytes blob = west.encrypt(r -> r.keyId(key).plaintext(sdk(9))).ciphertextBlob();
    assertThrows(IncorrectKeyException.class, () -> west.decrypt(r -> r.keyId(other).ciphertextBlob(blob)));
    assertThrows(
      InvalidKeyUsageException.class,
      () -> west.decrypt(r -> r.keyId(key).ciphertextBlob(blob).encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256))
    );
  }

  @Test
  void keyIdentifiers() {
    String key = aws.kms().createSymmetricKey(WEST);
    String id = key.substring(key.indexOf("key/") + 4);
    aws.kms().createAlias("alias/mine", key);
    String aliasArn = "arn:aws:kms:" + WEST + ":" + FakeKms.ACCOUNT + ":alias/mine";
    for (String identifier : Arrays.asList(key, id, "alias/mine", aliasArn)) {
      assertEquals(key, west.encrypt(r -> r.keyId(identifier).plaintext(sdk(1))).keyId(), identifier);
    }
    // Another region's ARN, a key id or alias that exists only in another region, and unknown names.
    for (String identifier : Arrays.asList(key, id, "alias/mine", aliasArn, "alias/other")) {
      assertThrows(NotFoundException.class, () -> east.encrypt(r -> r.keyId(identifier).plaintext(sdk(1))), identifier);
    }
    assertThrows(NotFoundException.class, () -> west.encrypt(r -> r.keyId("alias/other").plaintext(sdk(1))));
    assertThrows(NotFoundException.class, () -> west.encrypt(r -> r.keyId(key.replace("key/", "key/1")).plaintext(sdk(1))));
  }

  @Test
  void multiRegionKeyReplicasShareMaterial() {
    List<String> replicas = aws.kms().createMultiRegionKey(EAST, WEST);
    assertEquals(replicas.get(0).replace(EAST, WEST), replicas.get(1));
    assertEquals("mrk-", replicas.get(0).substring(replicas.get(0).indexOf("key/") + 4).substring(0, 4));
    SdkBytes blob = east.encrypt(r -> r.keyId(replicas.get(0)).plaintext(sdk(5)).encryptionContext(context)).ciphertextBlob();

    DecryptResponse decrypted = west.decrypt(r -> r.keyId(replicas.get(1)).ciphertextBlob(blob).encryptionContext(context));
    assertEquals(replicas.get(1), decrypted.keyId());
    assertArrayEquals(bytes(5), decrypted.plaintext().asByteArray());
    assertEquals(replicas.get(1), west.decrypt(r -> r.ciphertextBlob(blob).encryptionContext(context)).keyId());
    // Decrypt does not look up its KeyId: another region's ARN only fails to match the blob's key.
    assertThrows(IncorrectKeyException.class, () -> west.decrypt(r -> r.keyId(replicas.get(0)).ciphertextBlob(blob).encryptionContext(context)));

    // A single-Region key's ciphertext does not decrypt in another region.
    String single = aws.kms().createSymmetricKey(EAST);
    SdkBytes singleBlob = east.encrypt(r -> r.keyId(single).plaintext(sdk(5))).ciphertextBlob();
    assertEquals("AccessDeniedException", errorCode(() -> west.decrypt(r -> r.ciphertextBlob(singleBlob))));
  }

  // Error codes and messages observed on real KMS (report 27), for the cases the keyrings and key store reach.
  @Test
  void errorsMatchRealKms() throws GeneralSecurityException {
    String key = aws.kms().createSymmetricKey(WEST);
    String other = aws.kms().createSymmetricKey(WEST);
    String rsa = aws.kms().createRsaKey(WEST, "RSA_2048");
    String ecc = aws.kms().createEccKeyAgreementKey(WEST, "ECC_NIST_P256");
    List<String> replicas = aws.kms().createMultiRegionKey(WEST, EAST);
    SdkBytes blob = west.encrypt(r -> r.keyId(key).plaintext(sdk(5))).ciphertextBlob();
    SdkBytes replicaBlob = west.encrypt(r -> r.keyId(replicas.get(0)).plaintext(sdk(5))).ciphertextBlob();
    String prefix = key.substring(0, key.indexOf("key/"));

    KmsException denied = assertThrows(KmsException.class, () -> east.decrypt(r -> r.keyId(replicas.get(1)).ciphertextBlob(blob)));
    assertEquals("AccessDeniedException", denied.awsErrorDetails().errorCode());
    assertEquals(
      "User: arn:aws:sts::" + FakeKms.ACCOUNT + ":assumed-role/fake-role/fake-session is not authorized to perform: kms:Decrypt" +
        " on the resource associated with this ciphertext because the resource does not exist in this Region," +
        " no resource-based policies allow access, or a resource-based policy explicitly denies access",
      denied.awsErrorDetails().errorMessage()
    );
    KmsException reEncryptDenied = assertThrows(KmsException.class, () -> east.reEncrypt(r -> r.ciphertextBlob(blob).destinationKeyId(replicas.get(1))));
    assertTrue(reEncryptDenied.awsErrorDetails().errorMessage().contains("is not authorized to perform: kms:ReEncryptFrom on the resource"));

    // A Decrypt KeyId of another region, of no key, an unknown alias, an RSA key without its algorithm, or another key.
    for (String keyId : Arrays.asList(replicas.get(1), prefix + "key/00000000-0000-4000-8000-000000000000", "alias/none", rsa, other)) {
      IncorrectKeyException incorrect = assertThrows(IncorrectKeyException.class, () -> west.decrypt(r -> r.keyId(keyId).ciphertextBlob(blob)), keyId);
      assertEquals("The key ID in the request does not identify a CMK that can perform this operation.", incorrect.awsErrorDetails().errorMessage());
    }
    assertEquals(replicas.get(1), east.decrypt(r -> r.keyId(replicas.get(1)).ciphertextBlob(replicaBlob)).keyId());
    // ReEncrypt matches SourceKeyId the same way; an unknown destination is not found.
    for (String sourceKeyId : Arrays.asList(other, prefix + "key/00000000-0000-4000-8000-000000000000")) {
      assertThrows(IncorrectKeyException.class, () -> west.reEncrypt(r -> r.ciphertextBlob(blob).sourceKeyId(sourceKeyId).destinationKeyId(key)), sourceKeyId);
    }
    assertEquals(
      "Key '" + prefix + "key/00000000-0000-4000-8000-000000000000' does not exist",
      assertThrows(NotFoundException.class, () -> west.reEncrypt(r -> r.ciphertextBlob(blob).destinationKeyId(prefix + "key/00000000-0000-4000-8000-000000000000")))
        .awsErrorDetails()
        .errorMessage()
    );

    // With an RSA algorithm, Decrypt looks the key up like the other operations.
    assertEquals(
      "Invalid arn " + WEST,
      assertThrows(NotFoundException.class, () -> east.decrypt(r -> r.keyId(rsa).ciphertextBlob(blob).encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1)))
        .awsErrorDetails()
        .errorMessage()
    );
    assertEquals(
      "Algorithm RSAES_OAEP_SHA_1 is incompatible with key spec SYMMETRIC_DEFAULT.",
      assertThrows(InvalidKeyUsageException.class, () -> west.decrypt(r -> r.keyId(key).ciphertextBlob(blob).encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1)))
        .awsErrorDetails()
        .errorMessage()
    );
    assertNull(
      assertThrows(InvalidKeyUsageException.class, () -> west.decrypt(r -> r.keyId(ecc).ciphertextBlob(blob).encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)))
        .awsErrorDetails()
        .errorMessage()
    );

    assertEquals("Invalid arn " + WEST, assertThrows(NotFoundException.class, () -> east.encrypt(r -> r.keyId(key).plaintext(sdk(1)))).awsErrorDetails().errorMessage());
    assertEquals("Invalid arn " + WEST, assertThrows(NotFoundException.class, () -> east.getPublicKey(r -> r.keyId(ecc))).awsErrorDetails().errorMessage());
    assertEquals(
      "Key '" + prefix + "key/00000000-0000-4000-8000-000000000000' does not exist",
      assertThrows(NotFoundException.class, () -> west.encrypt(r -> r.keyId("00000000-0000-4000-8000-000000000000").plaintext(sdk(1)))).awsErrorDetails().errorMessage()
    );
    assertEquals(
      "Alias " + prefix + "alias/none is not found.",
      assertThrows(NotFoundException.class, () -> west.encrypt(r -> r.keyId("alias/none").plaintext(sdk(1)))).awsErrorDetails().errorMessage()
    );
    assertNull(assertThrows(UnsupportedOperationException.class, () -> west.getPublicKey(r -> r.keyId(key))).awsErrorDetails().errorMessage());
    KeyPair local = ecKeyPair("secp256r1");
    assertEquals(
      key + " key usage is ENCRYPT_DECRYPT which is not valid for DeriveSharedSecret.",
      assertThrows(
        InvalidKeyUsageException.class,
        () -> west.deriveSharedSecret(r -> r.keyId(key).keyAgreementAlgorithm(KeyAgreementAlgorithmSpec.ECDH).publicKey(SdkBytes.fromByteArray(local.getPublic().getEncoded())))
      )
        .awsErrorDetails()
        .errorMessage()
    );
    assertNull(assertThrows(InvalidCiphertextException.class, () -> west.decrypt(r -> r.ciphertextBlob(SdkBytes.fromByteArray(bytes(150))))).awsErrorDetails().errorMessage());
  }

  @Test
  void keysWithGivenArns() {
    String westArn = "arn:aws:kms:" + WEST + ":658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7";
    String eastArn = westArn.replace(WEST, EAST);
    String single = "arn:aws:kms:" + WEST + ":658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
    aws.kms().createSymmetricKeys(westArn, eastArn);
    aws.kms().createSymmetricKeys(single);
    SdkBytes blob = east.encrypt(r -> r.keyId(eastArn).plaintext(sdk(5)).encryptionContext(context)).ciphertextBlob();
    DecryptResponse decrypted = west.decrypt(r -> r.keyId(westArn).ciphertextBlob(blob).encryptionContext(context));
    assertEquals(westArn, decrypted.keyId());
    assertArrayEquals(bytes(5), decrypted.plaintext().asByteArray());
    // Separate calls make separate keys.
    assertThrows(IncorrectKeyException.class, () -> west.decrypt(r -> r.keyId(single).ciphertextBlob(blob).encryptionContext(context)));
    assertThrows(IllegalArgumentException.class, () -> aws.kms().createSymmetricKeys(single));
    assertThrows(IllegalArgumentException.class, () -> aws.kms().createSymmetricKeys("arn:aws:kms:" + WEST + ":658956600833:alias/a"));
  }

  @Test
  void reEncrypt() {
    String source = aws.kms().createSymmetricKey(WEST);
    String destination = aws.kms().createSymmetricKey(WEST);
    Map<String, String> destinationContext = context("purpose", "other");
    SdkBytes blob = west.encrypt(r -> r.keyId(source).plaintext(sdk(7, 7)).encryptionContext(context)).ciphertextBlob();
    ReEncryptResponse reEncrypted = west.reEncrypt(r ->
      r
        .ciphertextBlob(blob)
        .sourceKeyId(source)
        .sourceEncryptionContext(context)
        .destinationKeyId(destination)
        .destinationEncryptionContext(destinationContext)
        .grantTokens("token")
    );
    assertEquals(source, reEncrypted.sourceKeyId());
    assertEquals(destination, reEncrypted.keyId());
    assertArrayEquals(bytes(7, 7), decrypt(west, reEncrypted.ciphertextBlob(), destinationContext));
    assertThrows(InvalidCiphertextException.class, () -> decrypt(west, reEncrypted.ciphertextBlob(), context));
    assertThrows(
      InvalidCiphertextException.class,
      () -> west.reEncrypt(r -> r.ciphertextBlob(blob).destinationKeyId(destination).sourceEncryptionContext(destinationContext))
    );
    assertThrows(
      IncorrectKeyException.class,
      () -> west.reEncrypt(r -> r.ciphertextBlob(blob).sourceKeyId(destination).destinationKeyId(destination).sourceEncryptionContext(context))
    );
  }

  @Test
  void rsaKeyDecryptsOaep() throws GeneralSecurityException {
    String key = aws.kms().createRsaKey(WEST, "RSA_2048");
    GetPublicKeyResponse publicKey = west.getPublicKey(r -> r.keyId(key));
    assertEquals(key, publicKey.keyId());
    assertEquals(KeyUsageType.ENCRYPT_DECRYPT, publicKey.keyUsage());
    assertEquals("RSA_2048", publicKey.keySpecAsString());
    assertEquals(
      Arrays.asList(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1, EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256),
      publicKey.encryptionAlgorithms()
    );
    assertEquals(
      "-----BEGIN PUBLIC KEY-----\n" +
        Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(publicKey.publicKey().asByteArray()) +
        "\n-----END PUBLIC KEY-----\n",
      aws.kms().publicKeyPem(key)
    );
    PublicKey rsa = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKey.publicKey().asByteArray()));

    for (EncryptionAlgorithmSpec algorithm : Arrays.asList(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1, EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)) {
      SdkBytes ciphertext = SdkBytes.fromByteArray(oaepEncrypt(rsa, algorithm, bytes(4, 5, 6)));
      DecryptResponse decrypted = west.decrypt(r -> r.keyId(key).ciphertextBlob(ciphertext).encryptionAlgorithm(algorithm));
      assertEquals(key, decrypted.keyId());
      assertEquals(algorithm, decrypted.encryptionAlgorithm());
      assertArrayEquals(bytes(4, 5, 6), decrypted.plaintext().asByteArray());

      EncryptionAlgorithmSpec other = algorithm == EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1
        ? EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256
        : EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1;
      assertThrows(InvalidCiphertextException.class, () -> west.decrypt(r -> r.keyId(key).ciphertextBlob(ciphertext).encryptionAlgorithm(other)));
      // Without an algorithm, KMS reads the blob as a symmetric ciphertext.
      assertThrows(InvalidCiphertextException.class, () -> west.decrypt(r -> r.keyId(key).ciphertextBlob(ciphertext)));
      assertEquals(
        "ValidationException",
        errorCode(() -> west.decrypt(r -> r.keyId(key).ciphertextBlob(ciphertext).encryptionAlgorithm(algorithm).encryptionContext(context)))
      );
    }
    assertThrows(InvalidKeyUsageException.class, () -> west.encrypt(r -> r.keyId(key).plaintext(sdk(1))));
    assertThrows(InvalidKeyUsageException.class, () -> west.generateDataKey(r -> r.keyId(key).numberOfBytes(32)));
  }

  @Test
  void eccKeyAgreement() throws GeneralSecurityException {
    String[][] specs = { { "ECC_NIST_P256", "secp256r1" }, { "ECC_NIST_P384", "secp384r1" }, { "ECC_NIST_P521", "secp521r1" } };
    for (String[] spec : specs) {
      String key = aws.kms().createEccKeyAgreementKey(WEST, spec[0]);
      GetPublicKeyResponse publicKey = west.getPublicKey(r -> r.keyId(key));
      assertEquals(key, publicKey.keyId());
      assertEquals(KeyUsageType.KEY_AGREEMENT, publicKey.keyUsage());
      assertEquals(spec[0], publicKey.keySpecAsString());
      assertEquals(Collections.singletonList(KeyAgreementAlgorithmSpec.ECDH), publicKey.keyAgreementAlgorithms());
      PublicKey kmsPublic = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(publicKey.publicKey().asByteArray()));

      KeyPair local = ecKeyPair(spec[1]);
      byte[] secret = west
        .deriveSharedSecret(r ->
          r
            .keyId(key)
            .keyAgreementAlgorithm(KeyAgreementAlgorithmSpec.ECDH)
            .publicKey(SdkBytes.fromByteArray(local.getPublic().getEncoded()))
        )
        .sharedSecret()
        .asByteArray();
      KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
      agreement.init(local.getPrivate());
      agreement.doPhase(kmsPublic, true);
      assertArrayEquals(agreement.generateSecret(), secret, spec[0]);

      KeyPair otherCurve = ecKeyPair(spec[1].equals("secp256r1") ? "secp384r1" : "secp256r1");
      assertEquals(
        "ValidationException",
        errorCode(() ->
          west.deriveSharedSecret(r ->
            r.keyId(key).keyAgreementAlgorithm(KeyAgreementAlgorithmSpec.ECDH).publicKey(SdkBytes.fromByteArray(otherCurve.getPublic().getEncoded()))
          )
        )
      );
      // Without an RSA algorithm, KMS reads the blob as a symmetric ciphertext.
      assertThrows(InvalidCiphertextException.class, () -> west.decrypt(r -> r.keyId(key).ciphertextBlob(SdkBytes.fromByteArray(bytes(1)))));
    }
    String symmetric = aws.kms().createSymmetricKey(WEST);
    assertThrows(UnsupportedOperationException.class, () -> west.getPublicKey(r -> r.keyId(symmetric)));
    KeyPair local = ecKeyPair("secp256r1");
    assertThrows(
      InvalidKeyUsageException.class,
      () ->
        west.deriveSharedSecret(r ->
          r.keyId(symmetric).keyAgreementAlgorithm(KeyAgreementAlgorithmSpec.ECDH).publicKey(SdkBytes.fromByteArray(local.getPublic().getEncoded()))
        )
    );
  }

  @Test
  void injectedFailures() {
    String failing = aws.kms().createSymmetricKey(WEST);
    String working = aws.kms().createSymmetricKey(WEST);
    SdkBytes failingBlob = west.encrypt(r -> r.keyId(failing).plaintext(sdk(1))).ciphertextBlob();
    SdkBytes workingBlob = west.encrypt(r -> r.keyId(working).plaintext(sdk(1))).ciphertextBlob();

    aws.kms().fail("Decrypt", failing, ServiceError.accessDenied("no kms:Decrypt"));
    KmsException denied = assertThrows(KmsException.class, () -> west.decrypt(r -> r.ciphertextBlob(failingBlob)));
    assertEquals("AccessDeniedException", denied.awsErrorDetails().errorCode());
    assertEquals("no kms:Decrypt", denied.awsErrorDetails().errorMessage());
    assertEquals(400, denied.statusCode());
    assertEquals("AccessDeniedException", errorCode(() -> west.decrypt(r -> r.keyId(failing).ciphertextBlob(failingBlob))));
    assertArrayEquals(bytes(1), west.decrypt(r -> r.ciphertextBlob(workingBlob)).plaintext().asByteArray());
    west.encrypt(r -> r.keyId(failing).plaintext(sdk(1)));
    // A KeyId that names no key fails as in KMS, not with the failure configured for the blob's key.
    assertThrows(IncorrectKeyException.class, () -> west.decrypt(r -> r.keyId("alias/none").ciphertextBlob(failingBlob)));

    aws.kms().fail("GenerateDataKey", null, ServiceError.throttling("slow down"));
    assertEquals("ThrottlingException", errorCode(() -> west.generateDataKey(r -> r.keyId(working).numberOfBytes(32))));
    assertEquals("ThrottlingException", errorCode(() -> west.generateDataKey(r -> r.keyId("alias/none").numberOfBytes(32))));
    // Retries are off: one request per call.
    assertEquals(2, countOperation(aws.requests("west"), "GenerateDataKey"));

    aws.kms().fail("Encrypt", null, ServiceError.of("NotFoundException", "gone"));
    assertThrows(NotFoundException.class, () -> west.encrypt(r -> r.keyId(working).plaintext(sdk(1))));

    aws.kms().clearFailures();
    west.decrypt(r -> r.ciphertextBlob(failingBlob));
    west.generateDataKey(r -> r.keyId(working).numberOfBytes(32));
  }

  @Test
  void requestsAreRecordedPerClient() {
    String key = aws.kms().createSymmetricKey(WEST);
    aws.clearRequests();
    SdkBytes blob = west
      .encrypt(r -> r.keyId(key).plaintext(sdk(1)).encryptionContext(context("b", "2", "a", "1")).grantTokens("t2", "t1"))
      .ciphertextBlob();
    KmsClient other = aws.kmsClient("other", WEST);
    other.decrypt(r -> r.ciphertextBlob(blob).encryptionContext(context("a", "1", "b", "2")).grantTokens("t3"));
    assertEquals("AccessDeniedException", errorCode(() -> east.decrypt(r -> r.ciphertextBlob(blob))));

    List<RecordedRequest> westRequests = aws.requests("west");
    assertEquals(1, westRequests.size());
    RecordedRequest encrypt = westRequests.get(0);
    assertEquals("west", encrypt.client());
    assertEquals("kms", encrypt.service());
    assertEquals("Encrypt", encrypt.operation());
    assertEquals(WEST, encrypt.region());
    // Fields sorted, map entries sorted, list order kept.
    assertEquals(
      "kms Encrypt us-west-2 {\"EncryptionContext\":{\"a\":\"1\",\"b\":\"2\"},\"GrantTokens\":[\"t2\",\"t1\"],\"KeyId\":\"" +
        key + "\",\"Plaintext\":\"AQ==\"}",
      encrypt.describe()
    );
    assertEquals(
      "kms Encrypt us-west-2 {\"EncryptionContext\":{\"a\":\"<ignored>\",\"b\":\"2\"},\"GrantTokens\":[\"t2\",\"t1\"],\"KeyId\":\"" +
        key + "\",\"Plaintext\":\"<ignored>\"}",
      encrypt.describe("Plaintext", "a", "absent")
    );
    RecordedRequest decrypt = aws.requests("other").get(0);
    assertEquals("Decrypt", decrypt.operation());
    assertEquals(Base64.getEncoder().encodeToString(blob.asByteArray()), decrypt.body().get("CiphertextBlob").asText());
    assertEquals("[\"t3\"]", decrypt.body().get("GrantTokens").toString());
    assertEquals(1, aws.requests("east").size());
    assertEquals(Arrays.asList("west", "other", "east"), clients(aws.requests()));

    aws.clearRequests();
    assertEquals(0, aws.requests().size());
  }

  @Test
  void editedResponses() {
    String key = aws.kms().createSymmetricKey(WEST);
    String other = aws.kms().createSymmetricKey(WEST);
    aws.kms().editResponses("GenerateDataKey", key, r -> r.put("KeyId", "edited"));
    aws.kms().editResponses("Encrypt", r -> (com.fasterxml.jackson.databind.node.ObjectNode) r.without("CiphertextBlob"));
    assertEquals("edited", west.generateDataKey(r -> r.keyId(key).numberOfBytes(16)).keyId());
    assertEquals(other, west.generateDataKey(r -> r.keyId(other).numberOfBytes(16)).keyId());
    assertNull(west.encrypt(r -> r.keyId(other).plaintext(sdk(1))).ciphertextBlob());
    aws.kms().clearFailures();
    assertEquals(key, west.generateDataKey(r -> r.keyId(key).numberOfBytes(16)).keyId());
  }

  @Test
  void unknownOperationFails() {
    assertEquals("UnknownOperationException", errorCode(() -> west.listKeys()));
  }

  private static List<String> clients(List<RecordedRequest> requests) {
    String[] clients = new String[requests.size()];
    for (int i = 0; i < clients.length; i++) {
      clients[i] = requests.get(i).client();
    }
    return Arrays.asList(clients);
  }

  private static long countOperation(List<RecordedRequest> requests, String operation) {
    return requests.stream().filter(r -> r.operation().equals(operation)).count();
  }

  private static byte[] decrypt(KmsClient client, SdkBytes blob, Map<String, String> context) {
    return client.decrypt(r -> r.ciphertextBlob(blob).encryptionContext(context)).plaintext().asByteArray();
  }

  private static String errorCode(Runnable call) {
    return assertThrows(KmsException.class, call::run).awsErrorDetails().errorCode();
  }

  private static byte[] oaepEncrypt(PublicKey key, EncryptionAlgorithmSpec algorithm, byte[] plaintext) throws GeneralSecurityException {
    boolean sha1 = algorithm == EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1;
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
    cipher.init(
      Cipher.ENCRYPT_MODE,
      key,
      new OAEPParameterSpec(sha1 ? "SHA-1" : "SHA-256", "MGF1", sha1 ? MGF1ParameterSpec.SHA1 : MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)
    );
    return cipher.doFinal(plaintext);
  }

  private static KeyPair ecKeyPair(String curve) throws GeneralSecurityException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec(curve));
    return generator.generateKeyPair();
  }

  private static Map<String, String> context(String... pairs) {
    Map<String, String> context = new LinkedHashMap<>();
    for (int i = 0; i < pairs.length; i += 2) {
      context.put(pairs[i], pairs[i + 1]);
    }
    return context;
  }

  private static SdkBytes sdk(int... values) {
    return SdkBytes.fromByteArray(bytes(values));
  }

  private static byte[] bytes(int... values) {
    byte[] bytes = new byte[values.length];
    for (int i = 0; i < values.length; i++) {
      bytes[i] = (byte) values[i];
    }
    return bytes;
  }
}
