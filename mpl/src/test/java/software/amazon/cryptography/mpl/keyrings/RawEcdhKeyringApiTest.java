// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.mpl.AlgorithmSuite;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptionContext;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.SecretBytes;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnEncryptRequest;

// The public API parts the differential tests cannot reach: argument checks, copies, and accessors.
class RawEcdhKeyringApiTest {

  private static final AlgorithmSuite SUITE = AlgorithmSuite.fromBinaryId(new byte[] { 0x01, 0x78 });

  @Test
  void requiredArguments() {
    byte[] key = new byte[1];
    assertMessage("Missing value for required field `senderStaticPrivateKey`", () -> RawEcdhStaticConfigurations.rawPrivateKeyToStaticPublicKey(null, key));
    assertMessage("Missing value for required field `recipientPublicKey`", () -> RawEcdhStaticConfigurations.rawPrivateKeyToStaticPublicKey(SecretBytes.copyOf(key), null));
    assertMessage("Missing value for required field `recipientPublicKey`", () -> RawEcdhStaticConfigurations.ephemeralPrivateKeyToStaticPublicKey((byte[]) null));
    assertMessage("Missing value for required field `recipientStaticPrivateKey`", () -> RawEcdhStaticConfigurations.publicKeyDiscovery((SecretBytes) null));
    RawEcdhStaticConfigurations scheme = RawEcdhStaticConfigurations.ephemeralPrivateKeyToStaticPublicKey(key);
    assertMessage("Missing value for required field `keyAgreementScheme`", () -> RawEcdhKeyring.builder().curveSpec(EcdhCurveSpec.ECC_NIST_P256).build());
    assertMessage("Missing value for required field `curveSpec`", () -> RawEcdhKeyring.builder().keyAgreementScheme(scheme).build());
  }

  // The configurations copy the keys: clearing the caller's copies changes nothing.
  @Test
  void keysAreCopiedAndAccessorsReturnTheSettings() throws Exception {
    KeyPair sender = keyPair();
    KeyPair recipient = keyPair();
    SecretBytes senderPrivate = privatePem(sender);
    SecretBytes recipientPrivate = privatePem(recipient);
    byte[] recipientPublic = recipient.getPublic().getEncoded();
    RawEcdhStaticConfigurations staticScheme = RawEcdhStaticConfigurations.rawPrivateKeyToStaticPublicKey(senderPrivate, recipientPublic);
    RawEcdhStaticConfigurations ephemeralScheme = RawEcdhStaticConfigurations.ephemeralPrivateKeyToStaticPublicKey(recipientPublic);
    RawEcdhStaticConfigurations discoveryScheme = RawEcdhStaticConfigurations.publicKeyDiscovery(recipientPrivate);
    senderPrivate.destroy();
    recipientPrivate.destroy();
    Arrays.fill(recipientPublic, (byte) 0);

    assertEquals(RawEcdhStaticConfigurations.Kind.RAW_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY, staticScheme.kind());
    assertEquals(RawEcdhStaticConfigurations.Kind.EPHEMERAL_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY, ephemeralScheme.kind());
    assertEquals(RawEcdhStaticConfigurations.Kind.PUBLIC_KEY_DISCOVERY, discoveryScheme.kind());
    RawEcdhKeyring staticKeyring = keyring(staticScheme);
    RawEcdhKeyring discoveryKeyring = keyring(discoveryScheme);
    assertSame(staticScheme, staticKeyring.keyAgreementScheme());
    assertEquals(EcdhCurveSpec.ECC_NIST_P256, staticKeyring.curveSpec());

    for (RawEcdhKeyring encryptor : Arrays.asList(staticKeyring, keyring(ephemeralScheme))) {
      EncryptionMaterials encrypted = encryptor.onEncrypt(OnEncryptRequest.builder().materials(EncryptionMaterials.builder(SUITE).encryptionContext(EncryptionContext.of("a", "b")).build()).build());
      DecryptionMaterials start = DecryptionMaterials.builder(SUITE).encryptionContext(EncryptionContext.of("a", "b")).build();
      DecryptionMaterials decrypted = discoveryKeyring.onDecrypt(OnDecryptRequest.builder().materials(start).encryptedDataKeys(encrypted.encryptedDataKeys()).build());
      assertTrue(decrypted.plaintextDataKey().get().contentEquals(encrypted.plaintextDataKey().get()));
    }
  }

  private static RawEcdhKeyring keyring(RawEcdhStaticConfigurations scheme) {
    return RawEcdhKeyring.builder().keyAgreementScheme(scheme).curveSpec(EcdhCurveSpec.ECC_NIST_P256).build();
  }

  private static KeyPair keyPair() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    return generator.generateKeyPair();
  }

  private static SecretBytes privatePem(KeyPair pair) {
    String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(pair.getPrivate().getEncoded());
    return SecretBytes.copyOf(("-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n").getBytes(StandardCharsets.US_ASCII));
  }

  private static void assertMessage(String message, Runnable call) {
    assertEquals(message, assertThrows(ValidationException.class, call::run).getMessage());
  }
}
