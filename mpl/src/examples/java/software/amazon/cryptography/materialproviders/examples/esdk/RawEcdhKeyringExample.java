// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import software.amazon.cryptography.esdk.DecryptResponse;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.EcdhCurveSpec;
import software.amazon.cryptography.materialproviders.keyrings.RawEcdhKeyring;
import software.amazon.cryptography.materialproviders.keyrings.RawEcdhKeyAgreementScheme;

/**
 * Encrypts and decrypts messages with raw ECDH keyrings: each data key is wrapped under a key derived from an
 * ECDH key agreement between a sender and a recipient.
 *
 * <p>Shows a sender with a static key pair, a sender with a new key pair per message, and a recipient that
 * decrypts both with its private key alone.
 *
 * <p>No arguments; runs without AWS.
 */
public final class RawEcdhKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private RawEcdhKeyringExample() {}

  public static void main(String[] args) throws GeneralSecurityException {
    run();
  }

  public static void run() throws GeneralSecurityException {
    // 1. Instantiate the ESDK.
    EsdkClient esdk = EsdkClient.create();

    // 2. Create P-256 key pairs for the sender and the recipient; a real application loads them from its key storage.
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair sender = generator.generateKeyPair();
    KeyPair recipient = generator.generateKeyPair();

    // 3. Create the keyrings, one per key agreement scheme.
    // Static sender: the sender's private key and the recipient's public key; it can also decrypt what it wrote.
    Keyring staticSender = ecdhKeyring(
      RawEcdhKeyAgreementScheme.rawPrivateKeyToStaticPublicKey(sender.getPrivate(), recipient.getPublic())
    );
    // Ephemeral sender: a new key pair per message, so the sender keeps no private key and cannot decrypt.
    Keyring ephemeralSender = ecdhKeyring(
      RawEcdhKeyAgreementScheme.ephemeralPrivateKeyToStaticPublicKey(recipient.getPublic())
    );
    // Recipient: its private key, with the sender's public key read from each message, so it accepts any sender.
    // To accept only one sender, use rawPrivateKeyToStaticPublicKey with that sender's public key instead.
    Keyring recipientKeyring = ecdhKeyring(RawEcdhKeyAgreementScheme.publicKeyDiscovery(recipient.getPrivate()));

    // 4. Encrypt a message with each sender.
    Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");
    byte[] fromStatic = esdk
      .encrypt(b -> b.plaintext(EXAMPLE_DATA).keyring(staticSender).encryptionContext(encryptionContext))
      .ciphertext();
    byte[] fromEphemeral = esdk
      .encrypt(b -> b.plaintext(EXAMPLE_DATA).keyring(ephemeralSender).encryptionContext(encryptionContext))
      .ciphertext();

    // 5. The recipient decrypts both; the static sender decrypts its own.
    checkDecrypts(esdk, recipientKeyring, fromStatic, encryptionContext);
    checkDecrypts(esdk, recipientKeyring, fromEphemeral, encryptionContext);
    checkDecrypts(esdk, staticSender, fromStatic, encryptionContext);
  }

  private static Keyring ecdhKeyring(RawEcdhKeyAgreementScheme keyAgreementScheme) {
    return RawEcdhKeyring
      .builder()
      .curveSpec(EcdhCurveSpec.ECC_NIST_P256)
      .keyAgreementScheme(keyAgreementScheme)
      .build();
  }

  private static void checkDecrypts(
    EsdkClient esdk,
    Keyring keyring,
    byte[] ciphertext,
    Map<String, String> encryptionContext
  ) {
    DecryptResponse decryptResponse = esdk.decrypt(b ->
      b.ciphertext(ciphertext).keyring(keyring).encryptionContext(encryptionContext)
    );
    if (!Arrays.equals(decryptResponse.plaintext(), EXAMPLE_DATA)) {
      throw new IllegalStateException("Decrypted plaintext does not match");
    }
  }
}
