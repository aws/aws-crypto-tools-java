// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.dbesdk;

import java.util.Map;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsKeyring;
import software.amazon.cryptography.materialproviders.keyrings.MultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * Customer example (MultiKeyringExample): a KMS key generates the data key and a local AES key wraps a second copy,
 * so the item can be read without KMS, for example during a KMS outage.
 */
public final class MultiKeyringExample {

  private MultiKeyringExample() {}

  /**
   * @param kms a client in the key's Region; with real AWS, {@code KmsClient.create()}
   * @return the encrypted item, readable with either keyring
   */
  public static Map<String, String> encryptAndDecryptWithEitherKey(KmsClient kms, String kmsKeyArn, SecretBytes aesKey) {
    Keyring kmsKeyring = AwsKmsKeyring.builder().kmsKeyId(kmsKeyArn).kmsClient(kms).build();
    Keyring aesKeyring = RawAesKeyring
      .builder()
      .keyNamespace("my-key-namespace")
      .keyName("my-aes-key-name")
      .wrappingKey(aesKey)
      .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
      .build();
    Keyring multi = MultiKeyring.builder().generator(kmsKeyring).childKeyrings(aesKeyring).build();

    Map<String, String> item = ExampleItems.item("multiKeyringItem");
    Map<String, String> encrypted = ExampleItems.roundTrip(ExampleItems.encryptor(multi), item);
    ExampleItems.requireEqual(item, ExampleItems.encryptor(aesKeyring).decryptItem(encrypted));
    ExampleItems.requireEqual(item, ExampleItems.encryptor(kmsKeyring).decryptItem(encrypted));
    return encrypted;
  }
}
