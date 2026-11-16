// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Supplier;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.internal.primitives.RsaKeyGeneration;
import software.amazon.cryptography.oldapi.primitives.AtomicPrimitives;
import software.amazon.cryptography.oldapi.primitives.model.CompressPublicKeyInput;
import software.amazon.cryptography.oldapi.primitives.model.CryptoConfig;
import software.amazon.cryptography.oldapi.primitives.model.DecompressPublicKeyInput;
import software.amazon.cryptography.oldapi.primitives.model.DeriveSharedSecretInput;
import software.amazon.cryptography.oldapi.primitives.model.ECCPrivateKey;
import software.amazon.cryptography.oldapi.primitives.model.ECCPublicKey;
import software.amazon.cryptography.oldapi.primitives.model.ECDHCurveSpec;
import software.amazon.cryptography.oldapi.primitives.model.ECDSASignInput;
import software.amazon.cryptography.oldapi.primitives.model.ECDSASignatureAlgorithm;
import software.amazon.cryptography.oldapi.primitives.model.ECDSAVerifyInput;
import software.amazon.cryptography.oldapi.primitives.model.GenerateECCKeyPairInput;
import software.amazon.cryptography.oldapi.primitives.model.GenerateECCKeyPairOutput;
import software.amazon.cryptography.oldapi.primitives.model.GenerateECDSASignatureKeyInput;
import software.amazon.cryptography.oldapi.primitives.model.GenerateECDSASignatureKeyOutput;
import software.amazon.cryptography.oldapi.primitives.model.GenerateRSAKeyPairInput;
import software.amazon.cryptography.oldapi.primitives.model.GenerateRSAKeyPairOutput;
import software.amazon.cryptography.oldapi.primitives.model.GetPublicKeyFromPrivateKeyInput;
import software.amazon.cryptography.oldapi.primitives.model.GetRSAKeyModulusLengthInput;
import software.amazon.cryptography.oldapi.primitives.model.ParsePublicKeyInput;
import software.amazon.cryptography.oldapi.primitives.model.RSADecryptInput;
import software.amazon.cryptography.oldapi.primitives.model.RSAEncryptInput;
import software.amazon.cryptography.oldapi.primitives.model.RSAPaddingMode;
import software.amazon.cryptography.oldapi.primitives.model.ValidatePublicKeyInput;

// Differential tests against the published Dafny-based MPL for the RSA, ECDSA, and ECDH AtomicPrimitives operations,
// plus the fixed keys from the Dafny-based MPL's TestRSA.dfy and TestECDH.dfy.
// Randomized outputs (keys, signatures, RSA ciphertexts) are checked by having each library use the other's output.
class AsymmetricPrimitivesTest {

  private static final ECDHCurveSpec[] NIST_CURVES = {
    ECDHCurveSpec.ECC_NIST_P256,
    ECDHCurveSpec.ECC_NIST_P384,
    ECDHCurveSpec.ECC_NIST_P521,
  };
  private static final ByteBuffer ASDF = utf8("asdf");

  private final AtomicPrimitives primitives = AtomicPrimitives
    .builder()
    .CryptoConfig(CryptoConfig.builder().build())
    .build();
  private final Object reference = ReferenceMpl.atomicPrimitives();
  private final Map<String, Integer> outcomes = new TreeMap<>();

  // ---------------------------------------------------------------- RSA

  @Test
  void rsaModulusLengthOfTheDafnyVectors() throws IOException {
    for (JsonNode vector : vectors().get("rsaPublicKeys")) {
      GetRSAKeyModulusLengthInput input = GetRSAKeyModulusLengthInput.builder().publicKey(utf8(vector.get("pem").asText())).build();
      String outcome = assertSameOutcome("GetRSAKeyModulusLength", input, () -> primitives.GetRSAKeyModulusLength(input));
      assertEquals("GetRSAKeyModulusLengthOutput{length=" + vector.get("lengthBits").asInt() + "}", outcome);
    }
  }

  @Test
  void rsaModulusLengthFailures() throws IOException {
    List<ByteBuffer> keys = new ArrayList<>(malformedPems());
    for (int bits : new int[] { 64, 80, 81 }) {
      keys.add(rsaPublicPem(semiprime(bits)));
    }
    keys.add(rsaPublicPem(BigInteger.ONE.shiftLeft(2047).setBit(0)));
    keys.add(pemOf("PUBLIC KEY", der(new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption), new byte[] { 1 }))));
    keys.add(ecPublicPem());
    keys.add(privatePem(0));
    for (ByteBuffer key : keys) {
      GetRSAKeyModulusLengthInput input = GetRSAKeyModulusLengthInput.builder().publicKey(key).build();
      assertSameOutcome("GetRSAKeyModulusLength", input, () -> primitives.GetRSAKeyModulusLength(input));
    }
    assertBothOutcomesSeen("GetRSAKeyModulusLength");
    assertTrue(outcomes.containsKey("GetRSAKeyModulusLength throws OpaqueError"), outcomes.toString());
    assertTrue(outcomes.containsKey("GetRSAKeyModulusLength throws AwsCryptographicPrimitivesError"), outcomes.toString());
  }

  // Each library decrypts what the other encrypted under every padding, and both decrypt the same ciphertext alike.
  @Test
  void rsaRoundTripsWithTheDafnyKeyPairs() throws IOException {
    for (JsonNode pair : vectors().get("rsaKeyPairs")) {
      ByteBuffer publicKey = utf8(pair.get("publicPem").asText());
      ByteBuffer privateKey = utf8(pair.get("privatePem").asText());
      for (RSAPaddingMode padding : RSAPaddingMode.values()) {
        crossCheckRsa(padding, publicKey, privateKey, ASDF);
      }
    }
  }

  @Test
  void rsaEncryptFailures() throws IOException {
    JsonNode pair = vectors().get("rsaKeyPairs").get(0);
    ByteBuffer publicKey = utf8(pair.get("publicPem").asText());
    List<ByteBuffer> keys = new ArrayList<>(malformedPems());
    keys.add(utf8(pair.get("privatePem").asText()));
    keys.add(ecPublicPem());
    for (RSAPaddingMode padding : RSAPaddingMode.values()) {
      for (ByteBuffer key : keys) {
        RSAEncryptInput input = RSAEncryptInput.builder().padding(padding).publicKey(key).plaintext(ASDF).build();
        assertSameOutcome("RSAEncrypt", input, () -> primitives.RSAEncrypt(input));
      }
      RSAEncryptInput empty = RSAEncryptInput.builder().padding(padding).publicKey(publicKey).plaintext(bytes(0, 0)).build();
      assertSameOutcome("RSAEncrypt", empty, () -> primitives.RSAEncrypt(empty));
      // A 2048-bit key fits k - 11 bytes under PKCS #1 v1.5 and k - 2 hLen - 2 under OAEP.
      int maximum = 256 - (padding == RSAPaddingMode.PKCS1 ? 11 : 2 * hashLength(padding) + 2);
      for (int length : new int[] { maximum, maximum + 1 }) {
        RSAEncryptInput input = RSAEncryptInput.builder().padding(padding).publicKey(publicKey).plaintext(bytes(length, 7)).build();
        if (length == maximum) {
          crossCheckRsa(padding, publicKey, utf8(pair.get("privatePem").asText()), input.plaintext());
        } else {
          assertSameOutcome("RSAEncrypt", input, () -> primitives.RSAEncrypt(input));
        }
      }
    }
    assertTrue(outcomes.containsKey("RSAEncrypt throws OpaqueError"), outcomes.toString());
    assertTrue(outcomes.containsKey("RSAEncrypt throws AwsCryptographicPrimitivesError"), outcomes.toString());
  }

  @Test
  void rsaDecryptFailures() throws IOException {
    JsonNode pair = vectors().get("rsaKeyPairs").get(0);
    JsonNode otherPair = vectors().get("rsaKeyPairs").get(1);
    ByteBuffer publicKey = utf8(pair.get("publicPem").asText());
    ByteBuffer privateKey = utf8(pair.get("privatePem").asText());
    List<ByteBuffer> keys = new ArrayList<>(malformedPems());
    keys.add(publicKey);
    keys.add(utf8(otherPair.get("privatePem").asText()));
    keys.add(privatePem(0));
    keys.add(pkcs1PrivatePem(privateKey));
    for (RSAPaddingMode encryptPadding : RSAPaddingMode.values()) {
      ByteBuffer ciphertext = nativeRsaEncrypt(encryptPadding, publicKey, ASDF);
      List<ByteBuffer> ciphertexts = Arrays.asList(
        ciphertext,
        flipBit(ciphertext, 0),
        flipBit(ciphertext, 255),
        bytes(0, 0),
        bytes(255, 1),
        bytes(257, 1),
        bytes(256, 0xff)
      );
      for (RSAPaddingMode padding : RSAPaddingMode.values()) {
        for (ByteBuffer candidate : ciphertexts) {
          RSADecryptInput input = RSADecryptInput.builder().padding(padding).privateKey(privateKey).cipherText(candidate).build();
          assertSameOutcome("RSADecrypt", input, () -> primitives.RSADecrypt(input));
        }
        for (ByteBuffer key : keys) {
          RSADecryptInput input = RSADecryptInput.builder().padding(padding).privateKey(key).cipherText(ciphertext).build();
          assertSameOutcome("RSADecrypt", input, () -> primitives.RSADecrypt(input));
        }
      }
    }
    assertBothOutcomesSeen("RSADecrypt");
    assertTrue(outcomes.containsKey("RSADecrypt throws AwsCryptographicPrimitivesError"), outcomes.toString());
  }

  // BouncyCastle generates even lengths only; 82 bits is the shortest key.
  @Test
  void rsaKeyGeneration() throws IOException {
    for (int lengthBits : new int[] { 81, 511 }) {
      GenerateRSAKeyPairInput input = GenerateRSAKeyPairInput.builder().lengthBits(lengthBits).build();
      assertEquals(
        "throws java.lang.RuntimeException: Unable to create RSA Key Pair",
        assertSameOutcome("GenerateRSAKeyPair", input, () -> primitives.GenerateRSAKeyPair(input))
      );
    }
    for (int lengthBits : new int[] { 82, 512, 1024, 2048 }) {
      GenerateRSAKeyPairInput input = GenerateRSAKeyPairInput.builder().lengthBits(lengthBits).build();
      GenerateRSAKeyPairOutput generated = primitives.GenerateRSAKeyPair(input);
      Object referenceGenerated = ReferenceMpl.call(reference, "GenerateRSAKeyPair", input);
      ByteBuffer referencePublic = (ByteBuffer) get(referenceGenerated, "publicKey", "pem");
      ByteBuffer referencePrivate = (ByteBuffer) get(referenceGenerated, "privateKey", "pem");
      assertEquals(lengthBits, generated.publicKey().lengthBits());
      assertEquals(lengthBits, generated.privateKey().lengthBits());
      assertEquals(pemShape(referencePublic), pemShape(generated.publicKey().pem()));
      assertEquals(pemShape(referencePrivate), pemShape(generated.privateKey().pem()));
      for (ByteBuffer publicKey : Arrays.asList(generated.publicKey().pem(), referencePublic)) {
        GetRSAKeyModulusLengthInput length = GetRSAKeyModulusLengthInput.builder().publicKey(publicKey).build();
        assertEquals("GetRSAKeyModulusLengthOutput{length=" + lengthBits + "}", assertSameOutcome("GetRSAKeyModulusLength", length, () -> primitives.GetRSAKeyModulusLength(length)));
      }
      assertEquals(BigInteger.valueOf(65537), rsaPublicKey(generated.publicKey().pem()).getPublicExponent());
      if (lengthBits >= 1024) {
        crossCheckRsa(RSAPaddingMode.OAEP_SHA256, generated.publicKey().pem(), generated.privateKey().pem(), ASDF);
        crossCheckRsa(RSAPaddingMode.PKCS1, referencePublic, referencePrivate, ASDF);
      }
    }
    assertNotEquals(
      ReferenceMpl.describe(primitives.GenerateRSAKeyPair(GenerateRSAKeyPairInput.builder().lengthBits(1024).build())),
      ReferenceMpl.describe(primitives.GenerateRSAKeyPair(GenerateRSAKeyPairInput.builder().lengthBits(1024).build()))
    );
  }

  // The old API's input model rejects these lengths before the operation; the core checks them itself.
  @Test
  void rsaKeyGenerationRejectsLengthsOutsideTheRange() {
    for (int lengthBits : new int[] { 80, 4097 }) {
      ValidationException e = assertThrows(ValidationException.class, () -> RsaKeyGeneration.generateKeyPair(lengthBits));
      assertEquals("Unable to create RSA Key Pair", e.getMessage());
    }
  }

  // ---------------------------------------------------------------- ECDSA

  // Verification keys are compressed points; signing keys are BigInteger.toByteArray of the scalar.
  @Test
  void ecdsaKeyGenerationEncodings() {
    for (ECDSASignatureAlgorithm algorithm : ECDSASignatureAlgorithm.values()) {
      int fieldLength = algorithm == ECDSASignatureAlgorithm.ECDSA_P256 ? 32 : 48;
      int leadingZeros = 0;
      for (int i = 0; i < 40; i++) {
        GenerateECDSASignatureKeyInput input = GenerateECDSASignatureKeyInput.builder().signatureAlgorithm(algorithm).build();
        GenerateECDSASignatureKeyOutput generated = primitives.GenerateECDSASignatureKey(input);
        Object referenceGenerated = ReferenceMpl.call(reference, "GenerateECDSASignatureKey", input);
        assertEquals(algorithm, generated.signatureAlgorithm());
        for (GenerateECDSASignatureKeyOutput keys : Arrays.asList(generated, ecdsaKeys(referenceGenerated))) {
          byte[] verificationKey = array(keys.verificationKey());
          assertEquals(fieldLength + 1, verificationKey.length);
          assertTrue(verificationKey[0] == 2 || verificationKey[0] == 3);
          byte[] signingKey = array(keys.signingKey());
          BigInteger scalar = new BigInteger(signingKey);
          assertTrue(scalar.signum() > 0);
          assertArrayEquals(scalar.toByteArray(), signingKey);
          assertArrayEquals(verificationKey, compressedPoint(curveOf(algorithm), scalar));
        }
        leadingZeros += generated.signingKey().get(0) == 0 ? 1 : 0;
      }
      // About half the scalars have their top bit set and so a leading zero byte.
      assertTrue(leadingZeros > 0 && leadingZeros < 40, "keys with a leading zero: " + leadingZeros);
    }
  }

  // Signatures have a fixed length; each library verifies the other's, made with either library's keys.
  @Test
  void ecdsaSignaturesCrossVerify() {
    for (ECDSASignatureAlgorithm algorithm : ECDSASignatureAlgorithm.values()) {
      int signatureLength = algorithm == ECDSASignatureAlgorithm.ECDSA_P256 ? 71 : 103;
      GenerateECDSASignatureKeyInput generate = GenerateECDSASignatureKeyInput.builder().signatureAlgorithm(algorithm).build();
      for (int i = 0; i < 20; i++) {
        GenerateECDSASignatureKeyOutput keys = i % 2 == 0
          ? primitives.GenerateECDSASignatureKey(generate)
          : ecdsaKeys(ReferenceMpl.call(reference, "GenerateECDSASignatureKey", generate));
        ByteBuffer message = bytes(i * 7, i);
        ECDSASignInput sign = ECDSASignInput.builder().signatureAlgorithm(algorithm).signingKey(keys.signingKey()).message(message).build();
        ByteBuffer nativeSignature = primitives.ECDSASign(sign);
        ByteBuffer referenceSignature = (ByteBuffer) ReferenceMpl.call(reference, "ECDSASign", sign);
        assertEquals(signatureLength, nativeSignature.limit());
        assertEquals(signatureLength, referenceSignature.limit());
        assertNotEquals(nativeSignature, primitives.ECDSASign(sign));
        for (ByteBuffer signature : Arrays.asList(nativeSignature, referenceSignature)) {
          ECDSAVerifyInput verify = ECDSAVerifyInput
            .builder()
            .signatureAlgorithm(algorithm)
            .verificationKey(keys.verificationKey())
            .message(message)
            .signature(signature)
            .build();
          assertEquals("true", assertSameOutcome("ECDSAVerify", verify, () -> primitives.ECDSAVerify(verify)));
          ECDSAVerifyInput otherMessage = verify.toBuilder().message(bytes(i * 7 + 1, i)).build();
          assertEquals("false", assertSameOutcome("ECDSAVerify", otherMessage, () -> primitives.ECDSAVerify(otherMessage)));
        }
      }
    }
  }

  // Signing keys outside [1, n - 1], negative ones (top bit set), and the empty key.
  @Test
  void ecdsaSignWithUnusualSigningKeys() {
    for (ECDSASignatureAlgorithm algorithm : ECDSASignatureAlgorithm.values()) {
      BigInteger n = curveOf(algorithm).getN();
      List<byte[]> keys = Arrays.asList(
        new byte[0],
        new byte[] { 0 },
        new byte[] { 1 },
        new byte[] { (byte) 0xff },
        n.toByteArray(),
        n.add(BigInteger.ONE).toByteArray(),
        n.subtract(BigInteger.ONE).toByteArray(),
        Arrays.copyOfRange(n.toByteArray(), 1, n.toByteArray().length),
        filled(100, 0x11)
      );
      for (byte[] key : keys) {
        ECDSASignInput sign = ECDSASignInput.builder().signatureAlgorithm(algorithm).signingKey(ByteBuffer.wrap(key)).message(ASDF).build();
        String expected = ReferenceMpl.outcome(() -> ReferenceMpl.call(reference, "ECDSASign", sign));
        String actual = ReferenceMpl.outcome(() -> primitives.ECDSASign(sign));
        if (expected.startsWith("throws") || actual.startsWith("throws")) {
          assertEquals(expected, actual, "ECDSASign with key " + hex(key));
          count("ECDSASign", actual);
          continue;
        }
        count("ECDSASign", actual);
        // Both signed: each signature verifies, or fails to, under the key for the scalar mod n alike.
        BigInteger scalar = new BigInteger(key).mod(n);
        if (scalar.signum() == 0) {
          continue;
        }
        ByteBuffer verificationKey = ByteBuffer.wrap(compressedPoint(curveOf(algorithm), scalar));
        for (ByteBuffer signature : Arrays.asList(primitives.ECDSASign(sign), (ByteBuffer) ReferenceMpl.call(reference, "ECDSASign", sign))) {
          ECDSAVerifyInput verify = ECDSAVerifyInput
            .builder()
            .signatureAlgorithm(algorithm)
            .verificationKey(verificationKey)
            .message(ASDF)
            .signature(signature)
            .build();
          assertSameOutcome("ECDSAVerify", verify, () -> primitives.ECDSAVerify(verify));
        }
      }
    }
    assertBothOutcomesSeen("ECDSASign");
  }

  @Test
  void ecdsaVerifyWithMalformedVerificationKeys() {
    for (ECDSASignatureAlgorithm algorithm : ECDSASignatureAlgorithm.values()) {
      ECNamedCurveParameterSpec curve = curveOf(algorithm);
      GenerateECDSASignatureKeyOutput keys = primitives.GenerateECDSASignatureKey(
        GenerateECDSASignatureKeyInput.builder().signatureAlgorithm(algorithm).build()
      );
      ByteBuffer signature = primitives.ECDSASign(
        ECDSASignInput.builder().signatureAlgorithm(algorithm).signingKey(keys.signingKey()).message(ASDF).build()
      );
      byte[] valid = array(keys.verificationKey());
      byte[] x = Arrays.copyOfRange(valid, 1, valid.length);
      BigInteger p = curve.getCurve().getField().getCharacteristic();
      List<byte[]> verificationKeys = new ArrayList<>(Arrays.asList(
        new byte[0],
        new byte[] { 2 },
        new byte[] { 3 },
        withPrefix((byte) 4, x),
        withPrefix((byte) 0, x),
        withPrefix((byte) (5 - valid[0]), x),
        withPrefix(valid[0], concat(new byte[] { 0 }, x)),
        withPrefix(valid[0], concat(new byte[] { 1 }, x)),
        withPrefix(valid[0], unsigned(new BigInteger(1, x).add(p))),
        withPrefix(valid[0], filled(x.length, 0xff)),
        uncompressedPoint(curve, BigInteger.valueOf(5))
      ));
      verificationKeys.add(withPrefix(valid[0], unsigned(xWithoutPoint(curve))));
      // A key from the other curve.
      verificationKeys.add(compressedPoint(curveOf(otherSignature(algorithm)), BigInteger.valueOf(5)));
      for (byte[] key : verificationKeys) {
        ECDSAVerifyInput verify = ECDSAVerifyInput
          .builder()
          .signatureAlgorithm(algorithm)
          .verificationKey(ByteBuffer.wrap(key))
          .message(ASDF)
          .signature(signature)
          .build();
        assertSameOutcome("ECDSAVerify", verify, () -> primitives.ECDSAVerify(verify));
      }
    }
    assertBothOutcomesSeen("ECDSAVerify");
    assertTrue(outcomes.containsKey("ECDSAVerify throws AwsCryptographicPrimitivesError"), outcomes.toString());
    assertTrue(outcomes.containsKey("ECDSAVerify throws IllegalArgumentException"), outcomes.toString());
  }

  @Test
  void ecdsaVerifyWithMalformedSignatures() throws IOException {
    for (ECDSASignatureAlgorithm algorithm : ECDSASignatureAlgorithm.values()) {
      BigInteger n = curveOf(algorithm).getN();
      GenerateECDSASignatureKeyOutput keys = primitives.GenerateECDSASignatureKey(
        GenerateECDSASignatureKeyInput.builder().signatureAlgorithm(algorithm).build()
      );
      ByteBuffer signature = primitives.ECDSASign(
        ECDSASignInput.builder().signatureAlgorithm(algorithm).signingKey(keys.signingKey()).message(ASDF).build()
      );
      ASN1Sequence parsed = ASN1Sequence.getInstance(array(signature));
      BigInteger r = ASN1Integer.getInstance(parsed.getObjectAt(0)).getPositiveValue();
      BigInteger s = ASN1Integer.getInstance(parsed.getObjectAt(1)).getPositiveValue();
      byte[] der = array(signature);
      List<ByteBuffer> signatures = Arrays.asList(
        signature,
        bytes(0, 0),
        flipBit(signature, 0),
        flipBit(signature, der.length - 1),
        ByteBuffer.wrap(Arrays.copyOf(der, der.length - 1)),
        ByteBuffer.wrap(concat(der, new byte[] { 0 })),
        ByteBuffer.wrap(signatureDer(r, n.subtract(s))),
        ByteBuffer.wrap(signatureDer(r, s.add(n))),
        ByteBuffer.wrap(signatureDer(BigInteger.ZERO, s)),
        ByteBuffer.wrap(signatureDer(r, BigInteger.ZERO)),
        ByteBuffer.wrap(concat(unsigned(r), unsigned(s))),
        bytes(der.length, 0x30)
      );
      for (ByteBuffer candidate : signatures) {
        ECDSAVerifyInput verify = ECDSAVerifyInput
          .builder()
          .signatureAlgorithm(algorithm)
          .verificationKey(keys.verificationKey())
          .message(ASDF)
          .signature(candidate)
          .build();
        assertSameOutcome("ECDSAVerify", verify, () -> primitives.ECDSAVerify(verify));
        ECDSAVerifyInput otherAlgorithm = verify.toBuilder().signatureAlgorithm(otherSignature(algorithm)).build();
        assertSameOutcome("ECDSAVerify", otherAlgorithm, () -> primitives.ECDSAVerify(otherAlgorithm));
      }
    }
    assertTrue(outcomes.containsKey("ECDSAVerify returns false"), outcomes.toString());
    assertTrue(outcomes.containsKey("ECDSAVerify throws AwsCryptographicPrimitivesError"), outcomes.toString());
  }

  // The materials' JCA keys follow the same encodings as ECDSASign and ECDSAVerify.
  @Test
  void materialsKeysAgreeWithEcdsa() throws Exception {
    AlgorithmSuite suite = EsdkAlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384;
    for (int i = 0; i < 10; i++) {
      GenerateECDSASignatureKeyOutput keys = ecdsaKeys(
        ReferenceMpl.call(
          reference,
          "GenerateECDSASignatureKey",
          GenerateECDSASignatureKeyInput.builder().signatureAlgorithm(ECDSASignatureAlgorithm.ECDSA_P384).build()
        )
      );
      EncryptionMaterials encryption = EncryptionMaterials
        .builder(suite)
        .signingKeyPair(SecretBytes.copyOf(array(keys.signingKey())), array(keys.verificationKey()))
        .build();
      DecryptionMaterials decryption = DecryptionMaterials
        .builder(suite)
        .encryptionContext(EncryptionContext.of("aws-crypto-public-key", Base64.getEncoder().encodeToString(array(keys.verificationKey()))))
        .build();
      byte[] digest = java.security.MessageDigest.getInstance("SHA-384").digest(array(ASDF));
      Signature signer = Signature.getInstance("NONEwithECDSA");
      signer.initSign(encryption.signingPrivateKey().get());
      signer.update(digest);
      ByteBuffer jcaSignature = ByteBuffer.wrap(signer.sign());
      ECDSAVerifyInput verify = ECDSAVerifyInput
        .builder()
        .signatureAlgorithm(ECDSASignatureAlgorithm.ECDSA_P384)
        .verificationKey(keys.verificationKey())
        .message(ASDF)
        .signature(jcaSignature)
        .build();
      assertEquals(Boolean.TRUE, ReferenceMpl.call(reference, "ECDSAVerify", verify));
      ByteBuffer referenceSignature = (ByteBuffer) ReferenceMpl.call(
        reference,
        "ECDSASign",
        ECDSASignInput.builder().signatureAlgorithm(ECDSASignatureAlgorithm.ECDSA_P384).signingKey(keys.signingKey()).message(ASDF).build()
      );
      Signature verifier = Signature.getInstance("NONEwithECDSA");
      verifier.initVerify(decryption.verificationPublicKey().get());
      verifier.update(digest);
      assertTrue(verifier.verify(array(referenceSignature)));
    }
  }

  // A signing key with its top bit set is negative, as ECDSASign reads it; a compressed point may carry extra leading zeros.
  @Test
  void materialsKeysReadUnusualEncodingsAsEcdsaDoes() {
    AlgorithmSuite suite = EsdkAlgorithmSuite.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256;
    BigInteger n = curveOf(ECDSASignatureAlgorithm.ECDSA_P256).getN();
    byte[] negative = n.subtract(BigInteger.ONE).toByteArray();
    negative = Arrays.copyOfRange(negative, negative.length - 32, negative.length);
    byte[] verificationKey = compressedPoint(curveOf(ECDSASignatureAlgorithm.ECDSA_P256), BigInteger.valueOf(7));
    PrivateKey privateKey = EncryptionMaterials
      .builder(suite)
      .signingKeyPair(SecretBytes.copyOf(negative), verificationKey)
      .build()
      .signingPrivateKey()
      .get();
    assertEquals(new BigInteger(negative), ((java.security.interfaces.ECPrivateKey) privateKey).getS());
    byte[] padded = withPrefix(verificationKey[0], concat(new byte[] { 0 }, Arrays.copyOfRange(verificationKey, 1, 33)));
    PublicKey publicKey = DecryptionMaterials
      .builder(suite)
      .encryptionContext(EncryptionContext.of("aws-crypto-public-key", Base64.getEncoder().encodeToString(padded)))
      .build()
      .verificationPublicKey()
      .get();
    assertEquals(
      curveOf(ECDSASignatureAlgorithm.ECDSA_P256).getG().multiply(BigInteger.valueOf(7)).normalize().getAffineXCoord().toBigInteger(),
      ((java.security.interfaces.ECPublicKey) publicKey).getW().getAffineX()
    );
    byte[] offCurve = withPrefix((byte) 2, unsigned(xWithoutPoint(curveOf(ECDSASignatureAlgorithm.ECDSA_P256))));
    DecryptionMaterials materials = DecryptionMaterials
      .builder(suite)
      .encryptionContext(EncryptionContext.of("aws-crypto-public-key", Base64.getEncoder().encodeToString(offCurve)))
      .build();
    ValidationException e = assertThrows(ValidationException.class, materials::verificationPublicKey);
    assertEquals("Could not decode Elliptic Curve point due to: Y was invalid.", e.getMessage());
  }

  // ---------------------------------------------------------------- ECDH

  @Test
  void ecdhDafnyVectors() throws IOException {
    for (JsonNode vector : vectors().get("ecdhKeys")) {
      ECDHCurveSpec curve = ECDHCurveSpec.valueOf(vector.get("curve").asText());
      ByteBuffer privateKey = utf8(vector.get("privatePem").asText());
      String publicDer = "0x" + vector.get("publicDer").asText();
      String compressed = "0x" + vector.get("compressed").asText();
      GetPublicKeyFromPrivateKeyInput fromPrivate = GetPublicKeyFromPrivateKeyInput
        .builder()
        .eccCurve(curve)
        .privateKey(ECCPrivateKey.builder().pem(privateKey).build())
        .build();
      String derived = assertSameOutcome("GetPublicKeyFromPrivateKey", fromPrivate, () -> primitives.GetPublicKeyFromPrivateKey(fromPrivate));
      assertTrue(derived.endsWith("publicKey=" + publicDer + "}"), derived);
      ParsePublicKeyInput parse = ParsePublicKeyInput.builder().publicKey(hexBuffer(publicDer)).build();
      assertEquals(
        "ParsePublicKeyOutput{publicKey=ECCPublicKey{der=" + publicDer + "}}",
        assertSameOutcome("ParsePublicKey", parse, () -> primitives.ParsePublicKey(parse))
      );
      CompressPublicKeyInput compress = CompressPublicKeyInput
        .builder()
        .eccCurve(curve)
        .publicKey(ECCPublicKey.builder().der(hexBuffer(publicDer)).build())
        .build();
      assertEquals(
        "CompressPublicKeyOutput{compressedPublicKey=" + compressed + "}",
        assertSameOutcome("CompressPublicKey", compress, () -> primitives.CompressPublicKey(compress))
      );
      DecompressPublicKeyInput decompress = DecompressPublicKeyInput.builder().eccCurve(curve).compressedPublicKey(hexBuffer(compressed)).build();
      assertEquals(
        "DecompressPublicKeyOutput{publicKey=ECCPublicKey{der=" + publicDer + "}}",
        assertSameOutcome("DecompressPublicKey", decompress, () -> primitives.DecompressPublicKey(decompress))
      );
      ValidatePublicKeyInput validate = ValidatePublicKeyInput.builder().eccCurve(curve).publicKey(hexBuffer(publicDer)).build();
      assertEquals("ValidatePublicKeyOutput{success=true}", assertSameOutcome("ValidatePublicKey", validate, () -> primitives.ValidatePublicKey(validate)));
      for (ECDHCurveSpec otherCurve : ECDHCurveSpec.values()) {
        GetPublicKeyFromPrivateKeyInput wrongCurve = fromPrivate.toBuilder().eccCurve(otherCurve).build();
        assertSameOutcome("GetPublicKeyFromPrivateKey", wrongCurve, () -> primitives.GetPublicKeyFromPrivateKey(wrongCurve));
        ValidatePublicKeyInput validateOther = validate.toBuilder().eccCurve(otherCurve).build();
        assertSameOutcome("ValidatePublicKey", validateOther, () -> primitives.ValidatePublicKey(validateOther));
        DecompressPublicKeyInput decompressOther = decompress.toBuilder().eccCurve(otherCurve).build();
        assertSameOutcome("DecompressPublicKey", decompressOther, () -> primitives.DecompressPublicKey(decompressOther));
        CompressPublicKeyInput compressOther = compress.toBuilder().eccCurve(otherCurve).build();
        assertSameOutcome("CompressPublicKey", compressOther, () -> primitives.CompressPublicKey(compressOther));
      }
    }
    assertTrue(outcomes.containsKey("GetPublicKeyFromPrivateKey throws AwsCryptographicPrimitivesError"), outcomes.toString());
    assertTrue(outcomes.containsKey("GetPublicKeyFromPrivateKey throws OpaqueError"), outcomes.toString());
  }

  // The infinity and out-of-range points from TestECDH.dfy, with the Java messages it expects where it names one.
  @Test
  void ecdhInvalidPublicKeysFromTheDafnyTests() throws IOException {
    for (JsonNode vector : vectors().get("ecdhInvalidPublicKeys")) {
      ECDHCurveSpec curve = ECDHCurveSpec.valueOf(vector.get("curve").asText());
      ByteBuffer der = hexBuffer("0x" + vector.get("der").asText());
      ValidatePublicKeyInput validate = ValidatePublicKeyInput.builder().eccCurve(curve).publicKey(der).build();
      String outcome = assertSameOutcome("ValidatePublicKey", validate, () -> primitives.ValidatePublicKey(validate));
      assertTrue(outcome.startsWith("throws"), vector.get("name").asText() + ": " + outcome);
      if (!vector.get("javaMessage").isNull()) {
        String expected = "throws " + "software.amazon.cryptography.primitives.model.AwsCryptographicPrimitivesError: ";
        assertTrue(outcome.startsWith(expected), outcome);
        assertTrue(outcome.contains(vector.get("javaMessage").asText()), outcome);
      }
      ecdhPublicKeyOperations(curve, der);
    }
  }

  // A point on the curve with x = 0 parses and is on the curve, but fails the (0, p) range check: the only false result.
  @Test
  void ecdhValidatePublicKeyReturnsFalseForAZeroCoordinate() {
    int falses = 0;
    for (ECDHCurveSpec curve : NIST_CURVES) {
      ECNamedCurveParameterSpec spec = curveOf(curve);
      ECPoint point = pointWithZeroX(spec);
      if (point == null) {
        continue;
      }
      ByteBuffer der = ByteBuffer.wrap(ecSpki(curve, point.getEncoded(false)));
      ValidatePublicKeyInput validate = ValidatePublicKeyInput.builder().eccCurve(curve).publicKey(der).build();
      String outcome = assertSameOutcome("ValidatePublicKey", validate, () -> primitives.ValidatePublicKey(validate));
      assertEquals("ValidatePublicKeyOutput{success=false}", outcome);
      falses++;
      ecdhPublicKeyOperations(curve, der);
    }
    assertTrue(falses > 0, "no curve has a point with x = 0");
  }

  @Test
  void ecdhMalformedPublicKeys() throws IOException {
    for (ECDHCurveSpec curve : ECDHCurveSpec.values()) {
      List<ByteBuffer> keys = new ArrayList<>(Arrays.asList(
        bytes(0, 0),
        bytes(1, 0x30),
        bytes(20, 0x41),
        utf8("not a key"),
        ByteBuffer.wrap(der(new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption), new RSAPublicKey(BigInteger.valueOf(3233), BigInteger.valueOf(17))))),
        ByteBuffer.wrap(ecSpki(ECDHCurveSpec.ECC_NIST_P256, new byte[] { 4, 1, 2 })),
        ByteBuffer.wrap(ecSpki(ECDHCurveSpec.ECC_NIST_P256, curveOf(ECDHCurveSpec.ECC_NIST_P256).getG().getEncoded(true))),
        ByteBuffer.wrap(ecSpki(ECDHCurveSpec.ECC_NIST_P256, uncompressedPoint(curveOf(ECDHCurveSpec.ECC_NIST_P384), BigInteger.TEN)))
      ));
      byte[] valid = array(ecdhKeys(primitives.GenerateECCKeyPair(GenerateECCKeyPairInput.builder().eccCurve(ECDHCurveSpec.ECC_NIST_P256).build()))[1]);
      keys.add(ByteBuffer.wrap(Arrays.copyOf(valid, valid.length - 1)));
      keys.add(ByteBuffer.wrap(concat(valid, new byte[] { 0 })));
      keys.add(flipBit(ByteBuffer.wrap(valid), valid.length - 1));
      for (ByteBuffer der : keys) {
        ValidatePublicKeyInput validate = ValidatePublicKeyInput.builder().eccCurve(curve).publicKey(der).build();
        assertSameOutcome("ValidatePublicKey", validate, () -> primitives.ValidatePublicKey(validate));
        ecdhPublicKeyOperations(curve, der);
      }
    }
    assertTrue(outcomes.containsKey("ParsePublicKey throws AwsCryptographicPrimitivesError"), outcomes.toString());
    assertTrue(outcomes.containsKey("ParsePublicKey returns"), outcomes.toString());
  }

  @Test
  void ecdhMalformedPrivateKeys() throws IOException {
    for (ECDHCurveSpec curve : ECDHCurveSpec.values()) {
      List<ByteBuffer> keys = new ArrayList<>(malformedPems());
      keys.add(utf8(vectors().get("rsaKeyPairs").get(0).get("privatePem").asText()));
      keys.add(pemOf("PRIVATE KEY", new byte[] { 0x30, 0 }));
      keys.add(privatePem(0));
      for (ByteBuffer pem : keys) {
        ECCPrivateKey privateKey = ECCPrivateKey.builder().pem(pem).build();
        GetPublicKeyFromPrivateKeyInput fromPrivate = GetPublicKeyFromPrivateKeyInput.builder().eccCurve(curve).privateKey(privateKey).build();
        assertSameOutcome("GetPublicKeyFromPrivateKey", fromPrivate, () -> primitives.GetPublicKeyFromPrivateKey(fromPrivate));
        DeriveSharedSecretInput derive = DeriveSharedSecretInput
          .builder()
          .eccCurve(curve)
          .privateKey(privateKey)
          .publicKey(ECCPublicKey.builder().der(hexBuffer("0x" + vectors().get("ecdhKeys").get(0).get("publicDer").asText())).build())
          .build();
        assertSameOutcome("DeriveSharedSecret", derive, () -> primitives.DeriveSharedSecret(derive));
      }
    }
    assertTrue(outcomes.containsKey("GetPublicKeyFromPrivateKey throws IllegalArgumentException"), outcomes.toString());
  }

  // Private scalars outside [1, n - 1], in otherwise well-formed PKCS #8 keys.
  @Test
  void ecdhPrivateKeysWithScalarsOutOfRange() {
    for (ECDHCurveSpec curve : NIST_CURVES) {
      BigInteger n = curveOf(curve).getN();
      for (BigInteger scalar : Arrays.asList(BigInteger.ZERO, BigInteger.ONE, n.subtract(BigInteger.ONE), n, n.add(BigInteger.ONE))) {
        ECCPrivateKey privateKey = ECCPrivateKey.builder().pem(ecPrivatePem(curve, scalar)).build();
        GetPublicKeyFromPrivateKeyInput fromPrivate = GetPublicKeyFromPrivateKeyInput.builder().eccCurve(curve).privateKey(privateKey).build();
        assertSameOutcome("GetPublicKeyFromPrivateKey", fromPrivate, () -> primitives.GetPublicKeyFromPrivateKey(fromPrivate));
        DeriveSharedSecretInput derive = DeriveSharedSecretInput
          .builder()
          .eccCurve(curve)
          .privateKey(privateKey)
          .publicKey(ecdhKeyPair(curve).publicKey())
          .build();
        assertSameOutcome("DeriveSharedSecret", derive, () -> primitives.DeriveSharedSecret(derive));
      }
    }
  }

  @Test
  void ecdhMalformedCompressedPoints() {
    for (ECDHCurveSpec curve : ECDHCurveSpec.values()) {
      ECNamedCurveParameterSpec spec = curve == ECDHCurveSpec.SM2 ? curveOf(ECDHCurveSpec.ECC_NIST_P256) : curveOf(curve);
      byte[] valid = spec.getG().multiply(BigInteger.valueOf(3)).getEncoded(true);
      byte[] x = Arrays.copyOfRange(valid, 1, valid.length);
      List<byte[]> points = Arrays.asList(
        valid,
        new byte[0],
        new byte[] { 2 },
        withPrefix((byte) 4, x),
        withPrefix((byte) (5 - valid[0]), x),
        withPrefix(valid[0], concat(new byte[] { 0, 0 }, x)),
        withPrefix(valid[0], Arrays.copyOfRange(x, 1, x.length)),
        withPrefix(valid[0], unsigned(xWithoutPoint(spec))),
        withPrefix(valid[0], unsigned(new BigInteger(1, x).add(spec.getCurve().getField().getCharacteristic()))),
        spec.getG().getEncoded(false)
      );
      for (byte[] point : points) {
        DecompressPublicKeyInput decompress = DecompressPublicKeyInput.builder().eccCurve(curve).compressedPublicKey(ByteBuffer.wrap(point)).build();
        assertSameOutcome("DecompressPublicKey", decompress, () -> primitives.DecompressPublicKey(decompress));
      }
    }
    assertBothOutcomesSeen("DecompressPublicKey");
  }

  // Each library derives the public key and the shared secret from the other's key pairs.
  @Test
  void ecdhKeyGenerationAndAgreementCrossCheck() {
    for (ECDHCurveSpec curve : NIST_CURVES) {
      for (int i = 0; i < 5; i++) {
        GenerateECCKeyPairInput input = GenerateECCKeyPairInput.builder().eccCurve(curve).build();
        GenerateECCKeyPairOutput nativePair = primitives.GenerateECCKeyPair(input);
        Object referencePair = ReferenceMpl.call(reference, "GenerateECCKeyPair", input);
        ByteBuffer[] referenceKeys = ecdhKeys(referencePair);
        assertEquals(curve, nativePair.eccCurve());
        assertEquals(pemShape(referenceKeys[0]), pemShape(nativePair.privateKey().pem()));
        assertEquals(referenceKeys[0].limit(), nativePair.privateKey().pem().limit());
        assertEquals(referenceKeys[1].limit(), nativePair.publicKey().der().limit());
        for (ByteBuffer[] keys : Arrays.asList(ecdhKeys(nativePair), referenceKeys)) {
          GetPublicKeyFromPrivateKeyInput fromPrivate = GetPublicKeyFromPrivateKeyInput
            .builder()
            .eccCurve(curve)
            .privateKey(ECCPrivateKey.builder().pem(keys[0]).build())
            .build();
          String derived = assertSameOutcome("GetPublicKeyFromPrivateKey", fromPrivate, () -> primitives.GetPublicKeyFromPrivateKey(fromPrivate));
          assertTrue(derived.endsWith("publicKey=" + ReferenceMpl.describe(keys[1]) + "}"), derived);
          ecdhPublicKeyOperations(curve, keys[1]);
        }
        DeriveSharedSecretInput nativeSide = DeriveSharedSecretInput
          .builder()
          .eccCurve(curve)
          .privateKey(nativePair.privateKey())
          .publicKey(ECCPublicKey.builder().der(referenceKeys[1]).build())
          .build();
        DeriveSharedSecretInput referenceSide = DeriveSharedSecretInput
          .builder()
          .eccCurve(curve)
          .privateKey(ECCPrivateKey.builder().pem(referenceKeys[0]).build())
          .publicKey(nativePair.publicKey())
          .build();
        String secret = assertSameOutcome("DeriveSharedSecret", nativeSide, () -> primitives.DeriveSharedSecret(nativeSide));
        assertEquals(secret, assertSameOutcome("DeriveSharedSecret", referenceSide, () -> primitives.DeriveSharedSecret(referenceSide)));
        int fieldLength = curve == ECDHCurveSpec.ECC_NIST_P256 ? 32 : curve == ECDHCurveSpec.ECC_NIST_P384 ? 48 : 66;
        assertEquals("DeriveSharedSecretOutput{sharedSecret=0x".length() + 2 * fieldLength + 1, secret.length(), secret);
      }
    }
    GenerateECCKeyPairInput input = GenerateECCKeyPairInput.builder().eccCurve(ECDHCurveSpec.ECC_NIST_P256).build();
    assertNotEquals(ReferenceMpl.describe(primitives.GenerateECCKeyPair(input)), ReferenceMpl.describe(primitives.GenerateECCKeyPair(input)));
  }

  // The keys' own curves decide the agreement; the requested curve only excludes SM2.
  @Test
  void ecdhDeriveSharedSecretAcrossCurves() {
    for (ECDHCurveSpec privateCurve : NIST_CURVES) {
      GenerateECCKeyPairOutput pair = ecdhKeyPair(privateCurve);
      for (ECDHCurveSpec publicCurve : NIST_CURVES) {
        ECCPublicKey publicKey = ecdhKeyPair(publicCurve).publicKey();
        for (ECDHCurveSpec curve : ECDHCurveSpec.values()) {
          DeriveSharedSecretInput derive = DeriveSharedSecretInput
            .builder()
            .eccCurve(curve)
            .privateKey(pair.privateKey())
            .publicKey(publicKey)
            .build();
          assertSameOutcome("DeriveSharedSecret", derive, () -> primitives.DeriveSharedSecret(derive));
        }
      }
    }
    assertBothOutcomesSeen("DeriveSharedSecret");
    assertTrue(outcomes.containsKey("DeriveSharedSecret throws OpaqueError"), outcomes.toString());
  }

  // SM2 key generation works; every other SM2 operation reports it unsupported.
  @Test
  void ecdhSm2() {
    GenerateECCKeyPairInput input = GenerateECCKeyPairInput.builder().eccCurve(ECDHCurveSpec.SM2).build();
    BigInteger n = org.bouncycastle.asn1.gm.GMNamedCurves.getByName("sm2p256v1").getN();
    for (int i = 0; i < 10; i++) {
      for (ByteBuffer[] keys : Arrays.asList(ecdhKeys(primitives.GenerateECCKeyPair(input)), ecdhKeys(ReferenceMpl.call(reference, "GenerateECCKeyPair", input)))) {
        BigInteger d = new BigInteger(array(keys[0]));
        assertArrayEquals(d.toByteArray(), array(keys[0]));
        assertTrue(d.signum() > 0 && d.compareTo(n) < 0);
        assertArrayEquals(
          org.bouncycastle.asn1.gm.GMNamedCurves.getByName("sm2p256v1").getG().multiply(d).getEncoded(false),
          array(keys[1])
        );
      }
    }
    GenerateECCKeyPairOutput p256 = ecdhKeyPair(ECDHCurveSpec.ECC_NIST_P256);
    GetPublicKeyFromPrivateKeyInput fromPrivate = GetPublicKeyFromPrivateKeyInput.builder().eccCurve(ECDHCurveSpec.SM2).privateKey(p256.privateKey()).build();
    String outcome = assertSameOutcome("GetPublicKeyFromPrivateKey", fromPrivate, () -> primitives.GetPublicKeyFromPrivateKey(fromPrivate));
    assertEquals(
      "throws software.amazon.cryptography.primitives.model.OpaqueError: SM2 Not yet Supported. [obj java.lang.RuntimeException]",
      outcome
    );
    ValidatePublicKeyInput validate = ValidatePublicKeyInput.builder().eccCurve(ECDHCurveSpec.SM2).publicKey(p256.publicKey().der()).build();
    assertEquals(outcome, assertSameOutcome("ValidatePublicKey", validate, () -> primitives.ValidatePublicKey(validate)));
    DeriveSharedSecretInput derive = DeriveSharedSecretInput
      .builder()
      .eccCurve(ECDHCurveSpec.SM2)
      .privateKey(p256.privateKey())
      .publicKey(p256.publicKey())
      .build();
    assertEquals(outcome, assertSameOutcome("DeriveSharedSecret", derive, () -> primitives.DeriveSharedSecret(derive)));
    ecdhPublicKeyOperations(ECDHCurveSpec.SM2, p256.publicKey().der());
  }

  // ---------------------------------------------------------------- shared

  // Inputs are read as bytes [0, limit), ignoring position, as the Dafny-based MPL's conversion did.
  @Test
  void inputBuffersAreReadFromZeroToLimit() throws IOException {
    JsonNode rsaPair = vectors().get("rsaKeyPairs").get(0);
    JsonNode ecdh = vectors().get("ecdhKeys").get(0);
    GenerateECDSASignatureKeyOutput keys = primitives.GenerateECDSASignatureKey(
      GenerateECDSASignatureKeyInput.builder().signatureAlgorithm(ECDSASignatureAlgorithm.ECDSA_P256).build()
    );
    ByteBuffer message = bytes(10, 3);
    ByteBuffer signature = primitives.ECDSASign(
      ECDSASignInput.builder().signatureAlgorithm(ECDSASignatureAlgorithm.ECDSA_P256).signingKey(keys.signingKey()).message(message).build()
    );
    ByteBuffer ciphertext = nativeRsaEncrypt(RSAPaddingMode.OAEP_SHA1, utf8(rsaPair.get("publicPem").asText()), ASDF);
    for (int variant = 0; variant < 4; variant++) {
      ECDSAVerifyInput verify = ECDSAVerifyInput
        .builder()
        .signatureAlgorithm(ECDSASignatureAlgorithm.ECDSA_P256)
        .verificationKey(unusual(keys.verificationKey(), variant))
        .message(unusual(message, variant))
        .signature(unusual(signature, variant))
        .build();
      assertEquals("true", assertSameOutcome("ECDSAVerify", verify, () -> primitives.ECDSAVerify(verify)));
      RSADecryptInput decrypt = RSADecryptInput
        .builder()
        .padding(RSAPaddingMode.OAEP_SHA1)
        .privateKey(unusual(utf8(rsaPair.get("privatePem").asText()), variant))
        .cipherText(unusual(ciphertext, variant))
        .build();
      assertEquals(ReferenceMpl.describe(ASDF), assertSameOutcome("RSADecrypt", decrypt, () -> primitives.RSADecrypt(decrypt)));
      ParsePublicKeyInput parse = ParsePublicKeyInput.builder().publicKey(unusual(hexBuffer("0x" + ecdh.get("publicDer").asText()), variant)).build();
      assertTrue(assertSameOutcome("ParsePublicKey", parse, () -> primitives.ParsePublicKey(parse)).startsWith("ParsePublicKeyOutput"));
      GetPublicKeyFromPrivateKeyInput fromPrivate = GetPublicKeyFromPrivateKeyInput
        .builder()
        .eccCurve(ECDHCurveSpec.ECC_NIST_P256)
        .privateKey(ECCPrivateKey.builder().pem(unusual(utf8(ecdh.get("privatePem").asText()), variant)).build())
        .build();
      assertSameOutcome("GetPublicKeyFromPrivateKey", fromPrivate, () -> primitives.GetPublicKeyFromPrivateKey(fromPrivate));
    }
  }

  // The client is shared across threads; every thread must get the single-threaded answer.
  @Test
  void concurrentCallsAgree() throws Exception {
    JsonNode rsaPair = vectors().get("rsaKeyPairs").get(0);
    GenerateECCKeyPairOutput a = ecdhKeyPair(ECDHCurveSpec.ECC_NIST_P384);
    GenerateECCKeyPairOutput b = ecdhKeyPair(ECDHCurveSpec.ECC_NIST_P384);
    DeriveSharedSecretInput derive = DeriveSharedSecretInput.builder().eccCurve(ECDHCurveSpec.ECC_NIST_P384).privateKey(a.privateKey()).publicKey(b.publicKey()).build();
    RSADecryptInput decrypt = RSADecryptInput
      .builder()
      .padding(RSAPaddingMode.OAEP_SHA512)
      .privateKey(utf8(rsaPair.get("privatePem").asText()))
      .cipherText(nativeRsaEncrypt(RSAPaddingMode.OAEP_SHA512, utf8(rsaPair.get("publicPem").asText()), ASDF))
      .build();
    GenerateECDSASignatureKeyOutput keys = primitives.GenerateECDSASignatureKey(
      GenerateECDSASignatureKeyInput.builder().signatureAlgorithm(ECDSASignatureAlgorithm.ECDSA_P384).build()
    );
    ECDSASignInput sign = ECDSASignInput.builder().signatureAlgorithm(ECDSASignatureAlgorithm.ECDSA_P384).signingKey(keys.signingKey()).message(ASDF).build();
    String expectedSecret = ReferenceMpl.describe(primitives.DeriveSharedSecret(derive));
    String expectedPlaintext = ReferenceMpl.describe(primitives.RSADecrypt(decrypt));
    ExecutorService pool = Executors.newFixedThreadPool(8);
    try {
      List<Future<Boolean>> results = new ArrayList<>();
      for (int i = 0; i < 100; i++) {
        results.add(pool.submit(() -> {
          ECDSAVerifyInput verify = ECDSAVerifyInput
            .builder()
            .signatureAlgorithm(ECDSASignatureAlgorithm.ECDSA_P384)
            .verificationKey(keys.verificationKey())
            .message(ASDF)
            .signature(primitives.ECDSASign(sign))
            .build();
          return (
            expectedSecret.equals(ReferenceMpl.describe(primitives.DeriveSharedSecret(derive))) &&
            expectedPlaintext.equals(ReferenceMpl.describe(primitives.RSADecrypt(decrypt))) &&
            primitives.ECDSAVerify(verify)
          );
        }));
      }
      for (Future<Boolean> result : results) {
        assertTrue(result.get());
      }
    } finally {
      pool.shutdown();
    }
  }

  // ---------------------------------------------------------------- helpers

  // ParsePublicKey, CompressPublicKey, and DecompressPublicKey of the compressed form, for one public key.
  private void ecdhPublicKeyOperations(ECDHCurveSpec curve, ByteBuffer der) {
    ParsePublicKeyInput parse = ParsePublicKeyInput.builder().publicKey(der).build();
    assertSameOutcome("ParsePublicKey", parse, () -> primitives.ParsePublicKey(parse));
    CompressPublicKeyInput compress = CompressPublicKeyInput.builder().eccCurve(curve).publicKey(ECCPublicKey.builder().der(der).build()).build();
    assertSameOutcome("CompressPublicKey", compress, () -> primitives.CompressPublicKey(compress));
    try {
      ByteBuffer compressed = primitives.CompressPublicKey(compress).compressedPublicKey();
      DecompressPublicKeyInput decompress = DecompressPublicKeyInput.builder().eccCurve(curve).compressedPublicKey(compressed).build();
      assertSameOutcome("DecompressPublicKey", decompress, () -> primitives.DecompressPublicKey(decompress));
    } catch (RuntimeException notCompressible) {
      // The outcome was already compared above.
    }
  }

  private void crossCheckRsa(RSAPaddingMode padding, ByteBuffer publicKey, ByteBuffer privateKey, ByteBuffer plaintext) {
    RSAEncryptInput encrypt = RSAEncryptInput.builder().padding(padding).publicKey(publicKey).plaintext(plaintext).build();
    ByteBuffer nativeCiphertext = primitives.RSAEncrypt(encrypt);
    ByteBuffer referenceCiphertext = (ByteBuffer) ReferenceMpl.call(reference, "RSAEncrypt", encrypt);
    assertEquals(referenceCiphertext.limit(), nativeCiphertext.limit());
    assertNotEquals(nativeCiphertext, primitives.RSAEncrypt(encrypt));
    for (ByteBuffer ciphertext : Arrays.asList(nativeCiphertext, referenceCiphertext)) {
      RSADecryptInput decrypt = RSADecryptInput.builder().padding(padding).privateKey(privateKey).cipherText(ciphertext).build();
      assertEquals(ReferenceMpl.describe(plaintext), assertSameOutcome("RSADecrypt", decrypt, () -> primitives.RSADecrypt(decrypt)));
    }
  }

  private ByteBuffer nativeRsaEncrypt(RSAPaddingMode padding, ByteBuffer publicKey, ByteBuffer plaintext) {
    return primitives.RSAEncrypt(RSAEncryptInput.builder().padding(padding).publicKey(publicKey).plaintext(plaintext).build());
  }

  private GenerateECCKeyPairOutput ecdhKeyPair(ECDHCurveSpec curve) {
    return primitives.GenerateECCKeyPair(GenerateECCKeyPairInput.builder().eccCurve(curve).build());
  }

  // Also checks that neither library changed the caller's input.
  private String assertSameOutcome(String operation, Object input, Supplier<Object> nativeCall) {
    String before = ReferenceMpl.describe(input);
    String expected = ReferenceMpl.outcome(() -> ReferenceMpl.call(reference, operation, input));
    assertEquals(before, ReferenceMpl.describe(input), operation + ": the reference changed its input");
    String actual = withoutIdentityHashes(ReferenceMpl.outcome(nativeCall));
    expected = withoutIdentityHashes(expected);
    assertEquals(before, ReferenceMpl.describe(input), operation + ": the native library changed its input");
    assertEquals(expected, actual, operation + " on " + before);
    count(operation, actual);
    return actual;
  }

  // Some provider messages include Object.toString of a parameter object, such as "ECGenParameterSpec@60dd3c23".
  private static String withoutIdentityHashes(String outcome) {
    return outcome.replaceAll("@[0-9a-f]{4,8}\\b", "@<hash>");
  }

  // Counts "<operation> returns", "<operation> returns <value>" for booleans, and "<operation> throws <simple class name>".
  private void count(String operation, String outcome) {
    if (outcome.startsWith("throws ")) {
      String type = outcome.substring("throws ".length(), outcome.indexOf(':'));
      outcomes.merge(operation + " throws", 1, Integer::sum);
      outcomes.merge(operation + " throws " + type.substring(type.lastIndexOf('.') + 1), 1, Integer::sum);
    } else {
      outcomes.merge(operation + " returns", 1, Integer::sum);
      if (outcome.equals("true") || outcome.equals("false")) {
        outcomes.merge(operation + " returns " + outcome, 1, Integer::sum);
      }
    }
  }

  // Guards against a vacuous run in which every case succeeds or every case fails.
  private void assertBothOutcomesSeen(String operation) {
    assertTrue(outcomes.containsKey(operation + " returns"), operation + " never succeeded: " + outcomes);
    assertTrue(outcomes.containsKey(operation + " throws"), operation + " never failed: " + outcomes);
  }

  // PEM inputs that are not keys, or not well-formed PEM.
  private static List<ByteBuffer> malformedPems() {
    return Arrays.asList(
      bytes(0, 0),
      utf8("not a key"),
      utf8("-----BEGIN PUBLIC KEY-----\nMIIB\n"),
      utf8("-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n"),
      utf8("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"),
      utf8("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"),
      utf8("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
    );
  }

  private static ByteBuffer rsaPublicPem(BigInteger modulus) throws IOException {
    return pemOf("PUBLIC KEY", der(new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption), new RSAPublicKey(modulus, BigInteger.valueOf(65537)))));
  }

  // An RSA modulus of exactly {@code bits} bits with two prime factors, which BouncyCastle's key checks accept.
  private static BigInteger semiprime(int bits) {
    BigInteger p = BigInteger.ONE.shiftLeft(bits / 2 - 1).setBit(bits / 2 - 2).nextProbablePrime();
    BigInteger q = BigInteger.ONE.shiftLeft(bits - bits / 2 - 1).setBit(bits - bits / 2 - 2).nextProbablePrime();
    BigInteger n = p.multiply(q);
    assertEquals(bits, n.bitLength());
    return n;
  }

  private static RSAPublicKey rsaPublicKey(ByteBuffer pem) throws IOException {
    byte[] content = new PemReader(new java.io.StringReader(new String(array(pem), StandardCharsets.UTF_8))).readPemObject().getContent();
    return RSAPublicKey.getInstance(SubjectPublicKeyInfo.getInstance(content).parsePublicKey());
  }

  // The PKCS #1 RSAPrivateKey inside a PKCS #8 PEM key, as "RSA PRIVATE KEY".
  private static ByteBuffer pkcs1PrivatePem(ByteBuffer pkcs8Pem) throws IOException {
    byte[] content = new PemReader(new java.io.StringReader(new String(array(pkcs8Pem), StandardCharsets.UTF_8))).readPemObject().getContent();
    return pemOf("RSA PRIVATE KEY", org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(content).parsePrivateKey().toASN1Primitive().getEncoded());
  }

  private ByteBuffer ecPublicPem() {
    ByteBuffer der = ecdhKeys(ecdhKeyPair(ECDHCurveSpec.ECC_NIST_P256))[1];
    try {
      return pemOf("PUBLIC KEY", array(der));
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  // The PEM private key of a fresh ECDH key pair on the n-th NIST curve.
  private ByteBuffer privatePem(int curve) {
    return ecdhKeyPair(NIST_CURVES[curve]).privateKey().pem();
  }

  // A PKCS #8 EC private key with an arbitrary scalar and no public key.
  private static ByteBuffer ecPrivatePem(ECDHCurveSpec curve, BigInteger scalar) {
    try {
      org.bouncycastle.asn1.sec.ECPrivateKey key = new org.bouncycastle.asn1.sec.ECPrivateKey(curveOf(curve).getN().bitLength(), scalar);
      org.bouncycastle.asn1.pkcs.PrivateKeyInfo info = new org.bouncycastle.asn1.pkcs.PrivateKeyInfo(
        new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curveOid(curve)),
        key
      );
      return pemOf("PRIVATE KEY", info.getEncoded());
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  private static byte[] ecSpki(ECDHCurveSpec curve, byte[] point) {
    return der(new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curveOid(curve)), point));
  }

  private static ASN1ObjectIdentifier curveOid(ECDHCurveSpec curve) {
    return org.bouncycastle.asn1.x9.ECNamedCurveTable.getOID(curveName(curve));
  }

  private static ByteBuffer pemOf(String type, byte[] der) throws IOException {
    java.io.StringWriter text = new java.io.StringWriter();
    try (org.bouncycastle.util.io.pem.PemWriter writer = new org.bouncycastle.util.io.pem.PemWriter(text)) {
      writer.writeObject(new PemObject(type, der));
    }
    return utf8(text.toString());
  }

  private static byte[] der(ASN1Encodable value) {
    try {
      return value.toASN1Primitive().getEncoded("DER");
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  private static byte[] signatureDer(BigInteger r, BigInteger s) {
    return der(new DERSequence(new ASN1Encodable[] { new ASN1Integer(r), new ASN1Integer(s) }));
  }

  // The PEM's header and footer, whether every base64 line but the last has 64 characters, and the final newline.
  private static String pemShape(ByteBuffer pem) {
    String text = new String(array(pem), StandardCharsets.UTF_8);
    String[] lines = text.split("\n", -1);
    boolean fullLines = true;
    for (int i = 1; i < lines.length - 3; i++) {
      fullLines &= lines[i].length() == 64;
    }
    return lines[0] + " " + lines[lines.length - 2] + " full lines: " + fullLines + " final newline: " + text.endsWith("\n");
  }

  private static ECNamedCurveParameterSpec curveOf(ECDSASignatureAlgorithm algorithm) {
    return ECNamedCurveTable.getParameterSpec(algorithm == ECDSASignatureAlgorithm.ECDSA_P256 ? "secp256r1" : "secp384r1");
  }

  private static ECNamedCurveParameterSpec curveOf(ECDHCurveSpec curve) {
    return ECNamedCurveTable.getParameterSpec(curveName(curve));
  }

  private static String curveName(ECDHCurveSpec curve) {
    return curve == ECDHCurveSpec.ECC_NIST_P256 ? "secp256r1" : curve == ECDHCurveSpec.ECC_NIST_P384 ? "secp384r1" : "secp521r1";
  }

  private static ECDSASignatureAlgorithm otherSignature(ECDSASignatureAlgorithm algorithm) {
    return algorithm == ECDSASignatureAlgorithm.ECDSA_P256 ? ECDSASignatureAlgorithm.ECDSA_P384 : ECDSASignatureAlgorithm.ECDSA_P256;
  }

  private static byte[] compressedPoint(ECNamedCurveParameterSpec curve, BigInteger scalar) {
    return curve.getG().multiply(scalar).getEncoded(true);
  }

  private static byte[] uncompressedPoint(ECNamedCurveParameterSpec curve, BigInteger scalar) {
    return curve.getG().multiply(scalar).getEncoded(false);
  }

  // The smallest x > 1 with no point on the curve: x^3 + ax + b is not a square mod p.
  private static BigInteger xWithoutPoint(ECNamedCurveParameterSpec curve) {
    BigInteger p = curve.getCurve().getField().getCharacteristic();
    BigInteger a = curve.getCurve().getA().toBigInteger();
    BigInteger b = curve.getCurve().getB().toBigInteger();
    for (BigInteger x = BigInteger.valueOf(2);; x = x.add(BigInteger.ONE)) {
      BigInteger alpha = x.pow(3).add(a.multiply(x)).add(b).mod(p);
      if (!alpha.modPow(p.subtract(BigInteger.ONE).shiftRight(1), p).equals(BigInteger.ONE)) {
        return x;
      }
    }
  }

  // The point (0, sqrt(b)) if b is a square mod p, else null.
  private static ECPoint pointWithZeroX(ECNamedCurveParameterSpec curve) {
    BigInteger p = curve.getCurve().getField().getCharacteristic();
    BigInteger b = curve.getCurve().getB().toBigInteger();
    BigInteger y = b.modPow(p.add(BigInteger.ONE).shiftRight(2), p);
    if (!y.multiply(y).mod(p).equals(b)) {
      return null;
    }
    return curve.getCurve().createPoint(BigInteger.ZERO, y);
  }

  private static GenerateECDSASignatureKeyOutput ecdsaKeys(Object referenceOutput) {
    return GenerateECDSASignatureKeyOutput
      .builder()
      .signatureAlgorithm(ECDSASignatureAlgorithm.valueOf(String.valueOf(get(referenceOutput, "signatureAlgorithm"))))
      .verificationKey((ByteBuffer) get(referenceOutput, "verificationKey"))
      .signingKey((ByteBuffer) get(referenceOutput, "signingKey"))
      .build();
  }

  // {privateKey pem, publicKey der} of a GenerateECCKeyPairOutput from either library.
  private static ByteBuffer[] ecdhKeys(Object output) {
    return new ByteBuffer[] { (ByteBuffer) get(output, "privateKey", "pem"), (ByteBuffer) get(output, "publicKey", "der") };
  }

  // Follows public no-argument accessors on an object from either class loader.
  private static Object get(Object target, String... accessors) {
    Object value = target;
    for (String accessor : accessors) {
      try {
        value = value.getClass().getMethod(accessor).invoke(value);
      } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
        throw new IllegalStateException(e);
      }
    }
    return value;
  }

  private static JsonNode vectors() throws IOException {
    try (InputStream stream = AsymmetricPrimitivesTest.class.getResourceAsStream("/vectors/asymmetric.json")) {
      return new ObjectMapper().readTree(stream);
    }
  }

  private static int hashLength(RSAPaddingMode padding) {
    switch (padding) {
      case OAEP_SHA1:
        return 20;
      case OAEP_SHA256:
        return 32;
      case OAEP_SHA384:
        return 48;
      default:
        return 64;
    }
  }

  // variant 0: plain; 1: position past the start; 2: a slice with arrayOffset 8; 3: direct with position 1.
  private static ByteBuffer unusual(ByteBuffer value, int variant) {
    byte[] content = array(value);
    switch (variant) {
      case 0:
        return ByteBuffer.wrap(content);
      case 1: {
        ByteBuffer buffer = ByteBuffer.wrap(content);
        buffer.position(content.length / 2);
        return buffer;
      }
      case 2: {
        ByteBuffer outer = ByteBuffer.wrap(concat(filled(8, 0x55), content));
        outer.position(8);
        return outer.slice();
      }
      default: {
        ByteBuffer direct = ByteBuffer.allocateDirect(content.length);
        direct.put(content);
        direct.position(1);
        return direct;
      }
    }
  }

  private static ByteBuffer utf8(String text) {
    return ByteBuffer.wrap(text.getBytes(StandardCharsets.UTF_8));
  }

  private static ByteBuffer hexBuffer(String prefixedHex) {
    String text = prefixedHex.substring(2);
    byte[] bytes = new byte[text.length() / 2];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) Integer.parseInt(text.substring(2 * i, 2 * i + 2), 16);
    }
    return ByteBuffer.wrap(bytes);
  }

  private static String hex(byte[] bytes) {
    StringBuilder text = new StringBuilder();
    for (byte b : bytes) {
      text.append(String.format("%02x", b));
    }
    return text.toString();
  }

  private static ByteBuffer bytes(int length, int value) {
    return ByteBuffer.wrap(filled(length, value));
  }

  private static byte[] filled(int length, int value) {
    byte[] bytes = new byte[length];
    Arrays.fill(bytes, (byte) value);
    return bytes;
  }

  private static byte[] array(ByteBuffer buffer) {
    byte[] bytes = new byte[buffer.limit()];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = buffer.get(i);
    }
    return bytes;
  }

  private static byte[] concat(byte[] first, byte[] second) {
    byte[] both = Arrays.copyOf(first, first.length + second.length);
    System.arraycopy(second, 0, both, first.length, second.length);
    return both;
  }

  private static byte[] withPrefix(byte prefix, byte[] rest) {
    return concat(new byte[] { prefix }, rest);
  }

  // The unsigned big-endian bytes of a non-negative integer.
  private static byte[] unsigned(BigInteger value) {
    byte[] bytes = value.toByteArray();
    return bytes.length > 1 && bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
  }

  private static ByteBuffer flipBit(ByteBuffer buffer, int index) {
    byte[] bytes = array(buffer);
    bytes[index] ^= 1;
    return ByteBuffer.wrap(bytes);
  }
}
