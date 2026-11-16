// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Collections;
import java.util.Map;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.EcdhCurveSpec;
import software.amazon.cryptography.materialproviders.keyrings.RawEcdhKeyring;
import software.amazon.cryptography.materialproviders.keyrings.RawEcdhKeyAgreementScheme;

/**
 * Pattern (i): data keys wrapped under an ECDH-derived key. A sender with a static key pair, a sender with a new key pair
 * per message, and a recipient that decrypts both with its private key. No ESDK example yet; DB-ESDK has three.
 */
public final class RawEcdhKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private RawEcdhKeyringExample() {}

  public static void encryptAndDecrypt() throws GeneralSecurityException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair sender = generator.generateKeyPair();
    KeyPair recipient = generator.generateKeyPair();
    EsdkLikeClient crypto = EsdkLikeClient.builder().build();
    Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    Keyring staticSender = ecdh(RawEcdhKeyAgreementScheme.rawPrivateKeyToStaticPublicKey(sender.getPrivate(), recipient.getPublic()));
    Keyring ephemeralSender = ecdh(RawEcdhKeyAgreementScheme.ephemeralPrivateKeyToStaticPublicKey(recipient.getPublic()));
    Keyring recipientDiscovery = ecdh(RawEcdhKeyAgreementScheme.publicKeyDiscovery(recipient.getPrivate()));

    byte[] fromStatic = crypto.encryptData(staticSender, EXAMPLE_DATA, encryptionContext);
    byte[] fromEphemeral = crypto.encryptData(ephemeralSender, EXAMPLE_DATA, encryptionContext);
    Expect.equal(EXAMPLE_DATA, crypto.decryptData(recipientDiscovery, fromStatic, encryptionContext).getResult());
    Expect.equal(EXAMPLE_DATA, crypto.decryptData(recipientDiscovery, fromEphemeral, encryptionContext).getResult());
    // A static sender can read its own messages too.
    Expect.equal(EXAMPLE_DATA, crypto.decryptData(staticSender, fromStatic, encryptionContext).getResult());
  }

  private static Keyring ecdh(RawEcdhKeyAgreementScheme scheme) {
    return RawEcdhKeyring.builder().curveSpec(EcdhCurveSpec.ECC_NIST_P256).keyAgreementScheme(scheme).build();
  }
}
