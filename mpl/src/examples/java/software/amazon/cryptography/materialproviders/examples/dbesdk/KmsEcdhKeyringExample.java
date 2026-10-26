// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.dbesdk;

import java.util.Map;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsEcdhKeyring;
import software.amazon.cryptography.materialproviders.keyrings.EcdhCurveSpec;
import software.amazon.cryptography.materialproviders.keyrings.KmsEcdhStaticConfigurations;

/**
 * Customer example (KmsEcdhKeyringExample): ECDH with KMS key agreement keys on P-256.
 * The sender's KMS key derives the shared secret with the recipient's public key;
 * the recipient's discovery keyring decrypts with its own KMS key.
 */
public final class KmsEcdhKeyringExample {

  private KmsEcdhKeyringExample() {}

  /**
   * @param kms a client in the Region of both keys; with real AWS, {@code KmsClient.create()}
   * @return the encrypted item
   */
  public static Map<String, String> encryptAndDecrypt(KmsClient kms, String senderKeyArn, String recipientKeyArn) {
    // The recipient's public key as DER (X.509 SubjectPublicKeyInfo), which is what KMS returns.
    byte[] recipientPublicKey = kms.getPublicKey(request -> request.keyId(recipientKeyArn)).publicKey().asByteArray();

    AwsKmsEcdhKeyring sender = AwsKmsEcdhKeyring
      .builder()
      .curveSpec(EcdhCurveSpec.ECC_NIST_P256)
      .keyAgreementScheme(KmsEcdhStaticConfigurations.kmsPrivateKeyToStaticPublicKey(senderKeyArn, recipientPublicKey))
      .kmsClient(kms)
      .build();
    AwsKmsEcdhKeyring recipient = AwsKmsEcdhKeyring
      .builder()
      .curveSpec(EcdhCurveSpec.ECC_NIST_P256)
      .keyAgreementScheme(KmsEcdhStaticConfigurations.kmsPublicKeyDiscovery(recipientKeyArn))
      .kmsClient(kms)
      .build();

    Map<String, String> item = ExampleItems.item("kmsEcdhItem");
    Map<String, String> encrypted = ExampleItems.roundTrip(ExampleItems.encryptor(sender), item);
    ExampleItems.requireEqual(item, ExampleItems.encryptor(recipient).decryptItem(encrypted));
    return encrypted;
  }
}
