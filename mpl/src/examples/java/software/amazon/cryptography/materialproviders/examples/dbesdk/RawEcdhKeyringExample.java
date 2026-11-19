// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.dbesdk;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import software.amazon.cryptography.materialproviders.keyrings.EcdhCurveSpec;
import software.amazon.cryptography.materialproviders.keyrings.RawEcdhKeyring;
import software.amazon.cryptography.materialproviders.keyrings.RawEcdhKeyAgreementScheme;

/**
 * Customer example (RawEcdhKeyringExample): ECDH between local P-256 key pairs.
 * The sender's static key encrypts to the recipient; the recipient's discovery keyring decrypts any item addressed to it.
 * An ephemeral sender key encrypts without the sender holding a long-term private key.
 */
public final class RawEcdhKeyringExample {

  private RawEcdhKeyringExample() {}

  /**
   * @param sender a P-256 key pair of the sender, for example from {@code KeyPairGenerator.getInstance("EC")}
   * @param recipient a P-256 key pair of the recipient
   * @return the item encrypted with the sender's static key, then the item encrypted with an ephemeral key
   */
  public static List<Map<String, String>> encryptAndDecrypt(KeyPair sender, KeyPair recipient) {
    RawEcdhKeyring staticSender = RawEcdhKeyring
      .builder()
      .curveSpec(EcdhCurveSpec.ECC_NIST_P256)
      .keyAgreementScheme(
        RawEcdhKeyAgreementScheme
          .rawPrivateKeyToStaticPublicKey()
          .senderStaticPrivateKey(sender.getPrivate())
          .recipientPublicKey(recipient.getPublic())
          .build()
      )
      .build();
    RawEcdhKeyring ephemeralSender = RawEcdhKeyring
      .builder()
      .curveSpec(EcdhCurveSpec.ECC_NIST_P256)
      .keyAgreementScheme(
        RawEcdhKeyAgreementScheme
          .ephemeralPrivateKeyToStaticPublicKey()
          .recipientPublicKey(recipient.getPublic())
          .build()
      )
      .build();
    RawEcdhKeyring recipientDiscovery = RawEcdhKeyring
      .builder()
      .curveSpec(EcdhCurveSpec.ECC_NIST_P256)
      .keyAgreementScheme(
        RawEcdhKeyAgreementScheme
          .publicKeyDiscovery()
          .recipientStaticPrivateKey(recipient.getPrivate())
          .build()
      )
      .build();

    Map<String, String> item = ExampleItems.item("rawEcdhItem");
    DbEsdkLikeItemEncryptor recipientTable = ExampleItems.encryptor(recipientDiscovery);
    List<Map<String, String>> encrypted = new ArrayList<>();
    encrypted.add(ExampleItems.roundTrip(ExampleItems.encryptor(staticSender), item));
    encrypted.add(ExampleItems.encryptor(ephemeralSender).encryptItem(item));
    for (Map<String, String> each : encrypted) {
      ExampleItems.requireEqual(item, recipientTable.decryptItem(each));
    }
    return encrypted;
  }
}
