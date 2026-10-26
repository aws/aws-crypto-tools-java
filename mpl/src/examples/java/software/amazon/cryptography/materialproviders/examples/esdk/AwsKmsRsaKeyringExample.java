// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.examples.esdk.integration.CommitmentPolicy;
import software.amazon.cryptography.materialproviders.examples.esdk.integration.CryptoAlgorithm;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsRsaKeyring;

/**
 * Encrypt locally with the public key of an asymmetric KMS key; decrypt through KMS. The keyring rejects signing suites,
 * so the client names a suite without a signature. ESDK example: AwsKmsRsaKeyringExample.
 */
public final class AwsKmsRsaKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private AwsKmsRsaKeyringExample() {}

  /**
   * @param publicKeyPem the key's public key as UTF-8 PEM; real code writes it from {@code KmsClient.getPublicKey}
   * @param kmsClient real AWS: {@code KmsClient.create()}
   */
  public static void encryptAndDecrypt(String rsaKeyArn, byte[] publicKeyPem, KmsClient kmsClient) {
    EsdkLikeClient crypto = EsdkLikeClient
      .builder()
      .withEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256)
      .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
      .build();
    Keyring keyring = AwsKmsRsaKeyring
      .builder()
      .kmsKeyId(rsaKeyArn)
      .publicKey(publicKeyPem)
      .encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)
      .kmsClient(kmsClient)
      .build();
    Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    byte[] ciphertext = crypto.encryptData(keyring, EXAMPLE_DATA, encryptionContext);
    Expect.equal(EXAMPLE_DATA, crypto.decryptData(keyring, ciphertext, encryptionContext).getResult());
  }
}
