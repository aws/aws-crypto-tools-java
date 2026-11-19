// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keyrings;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
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
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

// The public API parts the differential tests cannot reach: argument checks, copies, and accessors.
class RawEcdhKeyringApiTest {

  private static final AlgorithmSuite SUITE = EsdkAlgorithmSuite.fromBinaryId(new byte[] { 0x01, 0x78 });

  @Test
  void requiredArguments() {
    byte[] key = new byte[1];
    assertMessage("Missing value for required field `senderStaticPrivateKey`", () -> RawEcdhKeyAgreementScheme.rawPrivateKeyToStaticPublicKey().senderStaticPrivateKey((SecretBytes) null).recipientPublicKey(key).build());
    assertMessage("Missing value for required field `recipientPublicKey`", () -> RawEcdhKeyAgreementScheme.rawPrivateKeyToStaticPublicKey().senderStaticPrivateKey(SecretBytes.copyOf(key)).recipientPublicKey((byte[]) null).build());
    assertMessage("Missing value for required field `recipientPublicKey`", () -> RawEcdhKeyAgreementScheme.ephemeralPrivateKeyToStaticPublicKey().recipientPublicKey((byte[]) null).build());
    assertMessage("Missing value for required field `recipientStaticPrivateKey`", () -> RawEcdhKeyAgreementScheme.publicKeyDiscovery().recipientStaticPrivateKey((SecretBytes) null).build());
    RawEcdhKeyAgreementScheme scheme = RawEcdhKeyAgreementScheme.ephemeralPrivateKeyToStaticPublicKey().recipientPublicKey(key).build();
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
    RawEcdhKeyAgreementScheme staticScheme = RawEcdhKeyAgreementScheme.rawPrivateKeyToStaticPublicKey().senderStaticPrivateKey(senderPrivate).recipientPublicKey(recipientPublic).build();
    RawEcdhKeyAgreementScheme ephemeralScheme = RawEcdhKeyAgreementScheme.ephemeralPrivateKeyToStaticPublicKey().recipientPublicKey(recipientPublic).build();
    RawEcdhKeyAgreementScheme discoveryScheme = RawEcdhKeyAgreementScheme.publicKeyDiscovery().recipientStaticPrivateKey(recipientPrivate).build();
    senderPrivate.destroy();
    recipientPrivate.destroy();
    Arrays.fill(recipientPublic, (byte) 0);

    assertEquals(RawEcdhKeyAgreementScheme.Kind.RAW_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY, staticScheme.kind());
    assertEquals(RawEcdhKeyAgreementScheme.Kind.EPHEMERAL_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY, ephemeralScheme.kind());
    assertEquals(RawEcdhKeyAgreementScheme.Kind.PUBLIC_KEY_DISCOVERY, discoveryScheme.kind());
    RawEcdhKeyring staticKeyring = keyring(staticScheme);
    RawEcdhKeyring discoveryKeyring = keyring(discoveryScheme);
    assertSame(staticScheme, staticKeyring.keyAgreementScheme());
    assertEquals(EcdhCurveSpec.ECC_NIST_P256, staticKeyring.curveSpec());

    for (RawEcdhKeyring encryptor : Arrays.asList(staticKeyring, keyring(ephemeralScheme))) {
      EncryptionMaterials encrypted = encryptor.onEncrypt(OnEncryptRequest.builder().materials(EncryptionMaterials.builder(SUITE).encryptionContext(EncryptionContext.of("a", "b")).build()).build()).materials();
      DecryptionMaterials start = DecryptionMaterials.builder(SUITE).encryptionContext(EncryptionContext.of("a", "b")).build();
      DecryptionMaterials decrypted = discoveryKeyring.onDecrypt(OnDecryptRequest.builder().materials(start).encryptedDataKeys(encrypted.encryptedDataKeys()).build()).materials();
      assertTrue(decrypted.plaintextDataKey().get().contentEquals(encrypted.plaintextDataKey().get()));
    }
  }

  // Each build() makes its own copies, so a builder can be reused and changed after building.
  @Test
  void schemeBuildersCopyPerBuildAndTakeAbsentOptionalKeys() throws Exception {
    KeyPair pair = keyPair();
    SecretBytes privateKey = privatePem(pair);
    byte[] publicKey = pair.getPublic().getEncoded();
    RawEcdhKeyAgreementScheme.RawPrivateKeyToStaticPublicKeyBuilder raw = RawEcdhKeyAgreementScheme
      .rawPrivateKeyToStaticPublicKey()
      .senderStaticPrivateKey(privateKey)
      .recipientPublicKey(publicKey);
    RawEcdhKeyAgreementScheme first = raw.build();
    RawEcdhKeyAgreementScheme second = raw.build();
    assertNotSame(first.privateKey(), second.privateKey());
    assertNotSame(first.recipientPublicKey(), second.recipientPublicKey());
    privateKey.destroy();
    Arrays.fill(publicKey, (byte) 0);
    assertArrayEquals(pair.getPublic().getEncoded(), first.recipientPublicKey());
    assertTrue(first.privateKey().contentEquals(privatePem(pair)));
    // The byte[] overload copies when set.
    byte[] privateBytes = privatePem(pair).toByteArray();
    RawEcdhKeyAgreementScheme.PublicKeyDiscoveryBuilder discovery = RawEcdhKeyAgreementScheme.publicKeyDiscovery().recipientStaticPrivateKey(privateBytes);
    Arrays.fill(privateBytes, (byte) 0);
    assertTrue(discovery.build().privateKey().contentEquals(privatePem(pair)));
    assertMessage("Missing value for required field `recipientStaticPrivateKey`", () -> RawEcdhKeyAgreementScheme.publicKeyDiscovery().build());
    assertMessage("Missing value for required field `recipientPublicKey`", () -> RawEcdhKeyAgreementScheme.ephemeralPrivateKeyToStaticPublicKey().build());
    assertMessage("Missing value for required field `senderStaticPrivateKey`", () -> RawEcdhKeyAgreementScheme.rawPrivateKeyToStaticPublicKey().recipientPublicKey(publicKey).build());
    // The KMS scheme's sender public key is optional: absent, the keyring fetches it.
    KmsEcdhKeyAgreementScheme fetched = KmsEcdhKeyAgreementScheme
      .kmsPrivateKeyToStaticPublicKey()
      .senderKmsIdentifier("arn")
      .senderPublicKey((byte[]) null)
      .recipientPublicKey(publicKey)
      .build();
    assertNull(fetched.senderPublicKey());
    assertMessage("Missing value for required field `recipientPublicKey`", () -> KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey().senderKmsIdentifier("arn").build());
    assertMessage("Missing value for required field `recipientKmsIdentifier`", () -> KmsEcdhKeyAgreementScheme.kmsPublicKeyDiscovery().build());
    assertEquals(KmsEcdhKeyAgreementScheme.Kind.KMS_PUBLIC_KEY_DISCOVERY, KmsEcdhKeyAgreementScheme.kmsPublicKeyDiscovery().recipientKmsIdentifier("arn").build().kind());
  }

  private static RawEcdhKeyring keyring(RawEcdhKeyAgreementScheme scheme) {
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
