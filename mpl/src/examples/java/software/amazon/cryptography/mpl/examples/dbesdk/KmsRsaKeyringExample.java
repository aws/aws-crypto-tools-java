// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples.dbesdk;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.cryptography.mpl.AlgorithmSuite;
import software.amazon.cryptography.mpl.keyrings.AwsKmsRsaKeyring;

/**
 * Customer example (KmsRsaKeyringExample): an asymmetric KMS RSA key.
 * Encryption uses the public key locally; only decryption calls KMS.
 * Like the DB-ESDK example, the table uses the suite without asymmetric signing.
 */
public final class KmsRsaKeyringExample {

  private KmsRsaKeyringExample() {}

  /**
   * @param kms a client in the key's Region; with real AWS, {@code KmsClient.create()}
   * @return the encrypted item
   */
  public static Map<String, String> encryptAndDecrypt(KmsClient kms, String rsaKeyArn) throws GeneralSecurityException {
    // KMS returns the public key as DER (X.509 SubjectPublicKeyInfo).
    byte[] publicKeyDer = kms.getPublicKey(request -> request.keyId(rsaKeyArn)).publicKey().asByteArray();
    PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyDer));

    AwsKmsRsaKeyring keyring = AwsKmsRsaKeyring
      .builder()
      .kmsKeyId(rsaKeyArn)
      .publicKey(publicKey)
      .encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)
      .kmsClient(kms)
      .build();
    DbEsdkLikeItemEncryptor encryptor = DbEsdkLikeItemEncryptor
      .builder()
      .logicalTableName(ExampleItems.TABLE)
      .partitionKeyName(ExampleItems.PARTITION_KEY)
      .sortKeyName(ExampleItems.SORT_KEY)
      .attributeActionsOnEncrypt(ExampleItems.actions())
      .keyring(keyring)
      .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384)
      .build();
    return ExampleItems.roundTrip(encryptor, ExampleItems.item("kmsRsaKeyringItem"));
  }
}
