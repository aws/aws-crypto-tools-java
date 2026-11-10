// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.cryptography.esdk.EncryptResponse;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsRsaKeyring;

/**
 * Encrypts with the public key of an asymmetric RSA KMS key, without calling KMS, and decrypts through KMS.
 *
 * <p>Arguments: the ARN of an RSA KMS key with key usage ENCRYPT_DECRYPT, in the SDK's default Region.
 * Calls KMS GetPublicKey and Decrypt.
 */
public final class KmsRsaKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private KmsRsaKeyringExample() {}

  public static void main(String[] args) throws GeneralSecurityException {
    if (args.length != 1) {
      throw new IllegalArgumentException("Arguments: <rsa-kms-key-arn>");
    }
    try (KmsClient kmsClient = KmsClient.create()) {
      run(args[0], kmsClient);
    }
  }

  public static void run(String rsaKeyArn, KmsClient kmsClient) throws GeneralSecurityException {
    // 1. Instantiate the ESDK.
    EsdkClient esdk = EsdkClient.create();

    // 2. Get the public key. A real application fetches it once and ships it to the parties that encrypt.
    byte[] publicKeyDer = kmsClient.getPublicKey(b -> b.keyId(rsaKeyArn)).publicKey().asByteArray();
    PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyDer));

    // 3. Create the keyrings.
    // The encrypting one needs only the public key; the decrypting one needs only a client for KMS Decrypt.
    Keyring encryptingKeyring = AwsKmsRsaKeyring
      .builder()
      .kmsKeyId(rsaKeyArn)
      .publicKey(publicKey)
      .encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)
      .build();
    Keyring decryptingKeyring = AwsKmsRsaKeyring
      .builder()
      .kmsKeyId(rsaKeyArn)
      .encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)
      .kmsClient(kmsClient)
      .build();

    // 4. Encrypt with a suite that does not sign, and decrypt.
    // A signature stops readers from writing messages; anyone with the public key can write them anyway.
    Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");
    EncryptResponse encryptResponse = esdk.encrypt(b ->
      b
        .plaintext(EXAMPLE_DATA)
        .keyring(encryptingKeyring)
        .encryptionContext(encryptionContext)
        .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
    );
    byte[] decrypted = esdk
      .decrypt(b ->
        b.ciphertext(encryptResponse.ciphertext()).keyring(decryptingKeyring).encryptionContext(encryptionContext)
      )
      .plaintext();
    if (!Arrays.equals(decrypted, EXAMPLE_DATA)) {
      throw new IllegalStateException("Decrypted plaintext does not match");
    }

    // 5. The keyring rejects the default suite, which signs.
    try {
      esdk.encrypt(b -> b.plaintext(EXAMPLE_DATA).keyring(encryptingKeyring));
      throw new IllegalStateException("The KMS RSA keyring encrypted with a signing suite");
    } catch (ValidationException expected) {
      // Choose a suite without a signature, as in step 4.
    }
  }
}
