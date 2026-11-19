// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keyrings;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

// The byte[] and SecretKey forms of secret settings behave as the SecretBytes form with the same bytes.
class SecretOverloadsTest {

  private static final AlgorithmSuite SUITE = EsdkAlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
  private static final EncryptionContext CONTEXT = EncryptionContext.of("a", "b");

  @Test
  void aesKeyFromBytesIsCopied() {
    byte[] key = new byte[32];
    Arrays.fill(key, (byte) 7);
    RawAesKeyring.Builder fromBytes = aes().wrappingKey(key);
    Arrays.fill(key, (byte) 0);
    byte[] same = new byte[32];
    Arrays.fill(same, (byte) 7);
    assertRoundTrip(fromBytes.build(), aes().wrappingKey(SecretBytes.copyOf(same)).build());
  }

  @Test
  void aesKeyFromSecretKey() {
    byte[] key = new byte[32];
    Arrays.fill(key, (byte) 9);
    assertRoundTrip(aes().wrappingKey(new SecretKeySpec(key, "AES")).build(), aes().wrappingKey(key).build());
  }

  // getEncoded() returns a new copy of the key each time; the keyring must not leave that copy behind.
  @Test
  void aesSecretKeyEncodingIsZeroed() {
    byte[] shared = new byte[32];
    Arrays.fill(shared, (byte) 5);
    aes().wrappingKey(new Unencoded("RAW", shared, true)).build();
    assertArrayEquals(new byte[32], shared);
  }

  @Test
  void aesSecretKeyWithoutRawEncodingIsRejected() {
    assertMessage("wrappingKey has no encoded form", () -> aes().wrappingKey(new Unencoded(null, null)));
    assertMessage("wrappingKey must use the RAW encoding format", () -> aes().wrappingKey(new Unencoded("PKCS#8", new byte[32])));
  }

  @Test
  void nullSecretsAreMissing() {
    assertMessage("Missing value for required field `wrappingKey`", () -> aes().wrappingKey((byte[]) null).build());
    assertMessage("Missing value for required field `wrappingKey`", () -> aes().wrappingKey((SecretKey) null).build());
    assertMessage("Missing value for required field `senderStaticPrivateKey`", () -> RawEcdhKeyAgreementScheme.rawPrivateKeyToStaticPublicKey().senderStaticPrivateKey((byte[]) null).recipientPublicKey(new byte[1]).build());
    assertMessage("Missing value for required field `recipientStaticPrivateKey`", () -> RawEcdhKeyAgreementScheme.publicKeyDiscovery().recipientStaticPrivateKey((byte[]) null).build());
  }

  @Test
  void rsaPrivateKeyFromBytes() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair pair = generator.generateKeyPair();
    byte[] pem = pem("PRIVATE KEY", pair.getPrivate().getEncoded());
    RawRsaKeyring encryptor = rsa().publicKey(pair.getPublic()).build();
    RawRsaKeyring.Builder decryptor = rsa().privateKey(pem);
    Arrays.fill(pem, (byte) 0);
    assertRoundTrip(encryptor, decryptor.build());
  }

  @Test
  void ecdhPrivateKeysFromBytes() throws Exception {
    KeyPair sender = ecKeyPair();
    KeyPair recipient = ecKeyPair();
    byte[] senderPem = pem("PRIVATE KEY", sender.getPrivate().getEncoded());
    byte[] recipientPem = pem("PRIVATE KEY", recipient.getPrivate().getEncoded());
    RawEcdhKeyAgreementScheme fromBytes = RawEcdhKeyAgreementScheme.rawPrivateKeyToStaticPublicKey().senderStaticPrivateKey(senderPem).recipientPublicKey(recipient.getPublic().getEncoded()).build();
    RawEcdhKeyAgreementScheme discovery = RawEcdhKeyAgreementScheme.publicKeyDiscovery().recipientStaticPrivateKey(recipientPem).build();
    byte[] expected = senderPem.clone();
    Arrays.fill(senderPem, (byte) 0);
    Arrays.fill(recipientPem, (byte) 0);
    assertArrayEquals(expected, fromBytes.privateKey().toByteArray());
    assertRoundTrip(ecdh(fromBytes), ecdh(discovery));
  }

  @Test
  void signingKeyPairFromBytes() {
    AlgorithmSuite signing = EsdkAlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
    byte[] signingKey = { 1, 2, 3 };
    EncryptionMaterials materials = EncryptionMaterials.builder(signing).signingKeyPair(signingKey, new byte[] { 4 }).build();
    Arrays.fill(signingKey, (byte) 0);
    assertArrayEquals(new byte[] { 1, 2, 3 }, materials.signingKey().get().toByteArray());
  }

  private static void assertRoundTrip(Keyring encryptor, Keyring decryptor) {
    EncryptionMaterials start = EncryptionMaterials.builder(SUITE).encryptionContext(CONTEXT).build();
    EncryptionMaterials encrypted = encryptor.onEncrypt(OnEncryptRequest.builder().materials(start).build()).materials();
    DecryptionMaterials decrypted = decryptor
      .onDecrypt(
        OnDecryptRequest
          .builder()
          .materials(DecryptionMaterials.builder(SUITE).encryptionContext(CONTEXT).build())
          .encryptedDataKeys(encrypted.encryptedDataKeys())
          .build()
      )
      .materials();
    assertTrue(decrypted.plaintextDataKey().get().contentEquals(encrypted.plaintextDataKey().get()));
  }

  private static RawAesKeyring.Builder aes() {
    return RawAesKeyring.builder().keyNamespace("ns").keyName("name").wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16);
  }

  private static RawRsaKeyring.Builder rsa() {
    return RawRsaKeyring.builder().keyNamespace("ns").keyName("name").paddingScheme(PaddingScheme.OAEP_SHA256_MGF1);
  }

  private static RawEcdhKeyring ecdh(RawEcdhKeyAgreementScheme scheme) {
    return RawEcdhKeyring.builder().keyAgreementScheme(scheme).curveSpec(EcdhCurveSpec.ECC_NIST_P256).build();
  }

  private static KeyPair ecKeyPair() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    return generator.generateKeyPair();
  }

  private static byte[] pem(String label, byte[] der) {
    String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
    return ("-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n").getBytes(StandardCharsets.US_ASCII);
  }

  private static void assertMessage(String message, Executable call) {
    assertEquals(message, assertThrows(ValidationException.class, call).getMessage());
  }

  // A key whose bytes are not exportable, or not in the RAW format.
  private static final class Unencoded implements SecretKey {

    private static final long serialVersionUID = 1L;
    private final String format;
    private final byte[] encoded;
    // Hands out the array itself, so a test can see what the caller does with it.
    private final boolean shared;

    Unencoded(String format, byte[] encoded) {
      this(format, encoded, false);
    }

    Unencoded(String format, byte[] encoded, boolean shared) {
      this.format = format;
      this.encoded = encoded;
      this.shared = shared;
    }

    @Override
    public String getAlgorithm() {
      return "AES";
    }

    @Override
    public String getFormat() {
      return format;
    }

    @Override
    public byte[] getEncoded() {
      return encoded == null || shared ? encoded : encoded.clone();
    }
  }
}
