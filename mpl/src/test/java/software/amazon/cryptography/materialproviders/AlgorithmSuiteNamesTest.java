// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.internal.primitives.Ecdsa;

// The JCA names on AlgorithmSuite, checked against what each constant's name says and against the JCA itself,
// and each format's fromBinaryId(int) against its fromBinaryId(byte[]), which AlgorithmSuitesTest compares with the reference for every 2-byte id.
class AlgorithmSuiteNamesTest {

  private static final Pattern KDF = Pattern.compile("_HKDF_SHA(\\d+)");
  private static final Pattern SIGNATURE = Pattern.compile("_ECDSA_P(\\d+)");
  private static final Pattern SYMMETRIC_SIGNATURE = Pattern.compile("_SYMSIG_HMAC_SHA(\\d+)");

  @Test
  void namesFollowTheConstantName() {
    for (AlgorithmSuite suite : AllSuites.all()) {
      String name = suite.name();
      assertEquals(group(KDF, name).map(bits -> "HmacSHA" + bits), suite.keyDerivation().hmacAlgorithm(), name);
      assertEquals(group(SIGNATURE, name).map(bits -> "SHA" + bits + "withECDSA"), suite.signature().map(AlgorithmSuite.Signature::jcaAlgorithm), name);
      assertEquals(group(SIGNATURE, name).map(bits -> "secp" + bits + "r1"), suite.signature().map(AlgorithmSuite.Signature::curveName), name);
      assertEquals(name.contains("_COMMIT_KEY") ? Optional.of("HmacSHA512") : Optional.empty(), suite.commitmentHmacAlgorithm(), name);
      assertEquals(group(SYMMETRIC_SIGNATURE, name).map(bits -> "HmacSHA" + bits), suite.symmetricSignatureHmacAlgorithm(), name);
    }
  }

  @Test
  void theJcaAcceptsEveryName() throws GeneralSecurityException {
    for (AlgorithmSuite suite : AllSuites.all()) {
      for (Optional<String> mac : Arrays.asList(suite.keyDerivation().hmacAlgorithm(), suite.commitmentHmacAlgorithm(), suite.symmetricSignatureHmacAlgorithm())) {
        if (mac.isPresent()) {
          assertEquals(mac.get(), Mac.getInstance(mac.get()).getAlgorithm());
        }
      }
    }
  }

  // A signature made with the materials' JCA key verifies under the suite's JCA name, and the curve name builds that curve.
  @Test
  void signatureNamesFitTheMaterialsKeys() throws GeneralSecurityException {
    byte[] message = "message".getBytes(StandardCharsets.UTF_8);
    for (AlgorithmSuite.Signature algorithm : AlgorithmSuite.Signature.values()) {
      AlgorithmSuite suite = algorithm == AlgorithmSuite.Signature.ECDSA_P256
        ? EsdkAlgorithmSuite.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
        : EsdkAlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384;
      byte[][] pair = Ecdsa.generateKeyPair(algorithm);
      EncryptionMaterials encryption = EncryptionMaterials.builder(suite).signingKeyPair(SecretBytes.copyOf(pair[1]), pair[0]).build();
      DecryptionMaterials decryption = DecryptionMaterials.builder(suite).encryptionContext(encryption.encryptionContext()).build();

      Signature signer = Signature.getInstance(algorithm.jcaAlgorithm());
      signer.initSign(encryption.signingPrivateKey().get());
      signer.update(message);
      byte[] signature = signer.sign();
      Signature verifier = Signature.getInstance(algorithm.jcaAlgorithm());
      verifier.initVerify(decryption.verificationPublicKey().get());
      verifier.update(message);
      assertTrue(verifier.verify(signature), algorithm.name());

      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(new ECGenParameterSpec(algorithm.curveName()));
      ECPublicKey generated = (ECPublicKey) generator.generateKeyPair().getPublic();
      ECPublicKey fromMaterials = (ECPublicKey) decryption.verificationPublicKey().get();
      assertEquals(fromMaterials.getParams().getCurve(), generated.getParams().getCurve(), algorithm.name());
    }
  }

  @Test
  void theIntLookupAgreesWithTheByteLookupForEveryTwoByteId() {
    for (int id = 0; id <= 0xFFFF; id++) {
      byte[] binaryId = { (byte) (id >> 8), (byte) id };
      final int same = id;
      assertLookupsAgree(() -> EsdkAlgorithmSuite.fromBinaryId(binaryId), () -> EsdkAlgorithmSuite.fromBinaryId(same));
      assertLookupsAgree(() -> DbeAlgorithmSuite.fromBinaryId(binaryId), () -> DbeAlgorithmSuite.fromBinaryId(same));
    }
    for (int outOfRange : new int[] { -1, 0x10000, 0x10478, 0x16700, Integer.MIN_VALUE }) {
      assertThrows(ValidationException.class, () -> EsdkAlgorithmSuite.fromBinaryId(outOfRange));
      assertThrows(ValidationException.class, () -> DbeAlgorithmSuite.fromBinaryId(outOfRange));
    }
  }

  private static void assertLookupsAgree(Supplier<AlgorithmSuite> bytes, Supplier<AlgorithmSuite> number) {
    AlgorithmSuite expected;
    try {
      expected = bytes.get();
    } catch (ValidationException e) {
      assertEquals(e.getMessage(), assertThrows(ValidationException.class, number::get).getMessage());
      return;
    }
    assertSame(expected, number.get());
  }

  private static Optional<String> group(Pattern pattern, String name) {
    Matcher matcher = pattern.matcher(name);
    return matcher.find() ? Optional.of(matcher.group(1)) : Optional.empty();
  }
}
