// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Supplier;
import javax.crypto.AEADBadTagException;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.primitives.AtomicPrimitives;
import software.amazon.cryptography.mpl.internal.primitives.KdfCounterMode;
import software.amazon.cryptography.primitives.model.AESDecryptInput;
import software.amazon.cryptography.primitives.model.AESEncryptInput;
import software.amazon.cryptography.primitives.model.AESEncryptOutput;
import software.amazon.cryptography.primitives.model.AES_GCM;
import software.amazon.cryptography.primitives.model.AesKdfCtrInput;
import software.amazon.cryptography.primitives.model.CryptoConfig;
import software.amazon.cryptography.primitives.model.DigestAlgorithm;
import software.amazon.cryptography.primitives.model.DigestInput;
import software.amazon.cryptography.primitives.model.GenerateRandomBytesInput;
import software.amazon.cryptography.primitives.model.HMacInput;
import software.amazon.cryptography.primitives.model.HkdfExpandInput;
import software.amazon.cryptography.primitives.model.HkdfExtractInput;
import software.amazon.cryptography.primitives.model.HkdfInput;
import software.amazon.cryptography.primitives.model.KdfCtrInput;
import software.amazon.cryptography.primitives.model.OpaqueError;

// Differential tests against the published Dafny-based MPL for the symmetric AtomicPrimitives operations,
// plus the RFC 5869 and SP 800-108 vectors from the Dafny-based MPL's own tests.
class SymmetricPrimitivesTest {

  private final AtomicPrimitives primitives = AtomicPrimitives
    .builder()
    .CryptoConfig(CryptoConfig.builder().build())
    .build();
  private final Object reference = ReferenceMpl.atomicPrimitives();
  private final Map<String, Integer> outcomes = new TreeMap<>();

  @Test
  void digest() {
    for (DigestAlgorithm algorithm : DigestAlgorithm.values()) {
      for (int length : new int[] { 0, 1, 55, 56, 64, 1000 }) {
        DigestInput input = DigestInput.builder().digestAlgorithm(algorithm).message(bytes(length, 7)).build();
        assertSameOutcome("Digest", input, () -> primitives.Digest(input));
      }
    }
  }

  @Test
  void hmac() {
    for (DigestAlgorithm algorithm : DigestAlgorithm.values()) {
      for (int keyLength : new int[] { 0, 1, 32, 200 }) {
        for (int messageLength : new int[] { 0, 10 }) {
          HMacInput input = HMacInput
            .builder()
            .digestAlgorithm(algorithm)
            .key(bytes(keyLength, 1))
            .message(bytes(messageLength, 2))
            .build();
          assertSameOutcome("HMac", input, () -> primitives.HMac(input));
        }
      }
    }
    assertBothOutcomesSeen("HMac");
  }

  @Test
  void hkdfExtract() {
    for (DigestAlgorithm algorithm : DigestAlgorithm.values()) {
      for (ByteBuffer salt : Arrays.asList(null, bytes(0, 0), bytes(1, 3), bytes(32, 3))) {
        for (int ikmLength : new int[] { 0, 16, 80 }) {
          HkdfExtractInput input = HkdfExtractInput
            .builder()
            .digestAlgorithm(algorithm)
            .salt(salt)
            .ikm(bytes(ikmLength, 4))
            .build();
          assertSameOutcome("HkdfExtract", input, () -> primitives.HkdfExtract(input));
        }
      }
    }
    assertBothOutcomesSeen("HkdfExtract");
  }

  @Test
  void hkdfExpand() {
    for (DigestAlgorithm algorithm : DigestAlgorithm.values()) {
      int hashLength = hashLength(algorithm);
      for (int prkLength : new int[] { hashLength - 1, hashLength, hashLength + 1 }) {
        for (int infoLength : new int[] { 0, 10 }) {
          for (int length : new int[] { 0, 1, hashLength, hashLength + 1, 255 * hashLength, 255 * hashLength + 1 }) {
            HkdfExpandInput input = HkdfExpandInput
              .builder()
              .digestAlgorithm(algorithm)
              .prk(bytes(prkLength, 5))
              .info(bytes(infoLength, 6))
              .expectedLength(length)
              .build();
            assertSameOutcome("HkdfExpand", input, () -> primitives.HkdfExpand(input));
          }
        }
      }
    }
    assertBothOutcomesSeen("HkdfExpand");
  }

  @Test
  void hkdf() {
    for (DigestAlgorithm algorithm : DigestAlgorithm.values()) {
      int hashLength = hashLength(algorithm);
      for (ByteBuffer salt : Arrays.asList(null, bytes(0, 0), bytes(16, 3))) {
        for (int ikmLength : new int[] { 0, 32 }) {
          for (int infoLength : new int[] { 0, 5 }) {
            for (int length : new int[] { 0, 1, 42, 255 * hashLength, 255 * hashLength + 1 }) {
              HkdfInput input = HkdfInput
                .builder()
                .digestAlgorithm(algorithm)
                .salt(salt)
                .ikm(bytes(ikmLength, 4))
                .info(bytes(infoLength, 6))
                .expectedLength(length)
                .build();
              assertSameOutcome("Hkdf", input, () -> primitives.Hkdf(input));
            }
          }
        }
      }
    }
    assertBothOutcomesSeen("Hkdf");
  }

  @Test
  void kdfCounterMode() {
    for (DigestAlgorithm algorithm : DigestAlgorithm.values()) {
      for (int ikmLength : new int[] { 31, 32, 48, 66 }) {
        for (int length : new int[] { 16, 32, 64 }) {
          for (ByteBuffer nonce : Arrays.asList(null, bytes(8, 1), bytes(16, 1), bytes(32, 1))) {
            for (ByteBuffer purpose : Arrays.asList(null, bytes(0, 0), ByteBuffer.wrap("aws-kms-hierarchy".getBytes()))) {
              KdfCtrInput input = KdfCtrInput
                .builder()
                .digestAlgorithm(algorithm)
                .ikm(bytes(ikmLength, 9))
                .expectedLength(length)
                .nonce(nonce)
                .purpose(purpose)
                .build();
              assertSameOutcome("KdfCounterMode", input, () -> primitives.KdfCounterMode(input));
            }
          }
        }
      }
    }
    assertBothOutcomesSeen("KdfCounterMode");
  }

  // Inputs are read as bytes [0, limit), ignoring position, as the Dafny-based MPL's conversion did.
  @Test
  void inputBuffersAreReadFromZeroToLimit() {
    for (ByteBuffer buffer : Arrays.asList(consumed(32), sliced(32), consumed(32).asReadOnlyBuffer(), direct(32))) {
      DigestInput digest = DigestInput.builder().digestAlgorithm(DigestAlgorithm.SHA_256).message(buffer).build();
      assertSameOutcome("Digest", digest, () -> primitives.Digest(digest));
      HMacInput hmac = HMacInput.builder().digestAlgorithm(DigestAlgorithm.SHA_256).key(buffer).message(buffer).build();
      assertSameOutcome("HMac", hmac, () -> primitives.HMac(hmac));
      HkdfExpandInput expand = HkdfExpandInput
        .builder()
        .digestAlgorithm(DigestAlgorithm.SHA_256)
        .prk(buffer)
        .info(buffer)
        .expectedLength(16)
        .build();
      assertSameOutcome("HkdfExpand", expand, () -> primitives.HkdfExpand(expand));
      AESEncryptInput aes = AESEncryptInput
        .builder()
        .encAlg(AES_GCM.builder().keyLength(32).ivLength(12).tagLength(16).build())
        .key(buffer)
        .iv(consumed(12))
        .msg(buffer)
        .aad(buffer)
        .build();
      assertSameOutcome("AESEncrypt", aes, () -> primitives.AESEncrypt(aes));
    }
  }

  @Test
  void aesKdfCounterModeAlwaysFails() {
    AesKdfCtrInput input = AesKdfCtrInput.builder().ikm(bytes(32, 1)).expectedLength(32).nonce(bytes(16, 2)).build();
    String outcome = assertSameOutcome("AesKdfCounterMode", input, () -> primitives.AesKdfCounterMode(input));
    assertTrue(outcome.startsWith("throws"), outcome);
  }

  @Test
  void aesEncryptAndDecrypt() {
    for (int keyLength : new int[] { 5, 16, 24, 32 }) {
      for (int ivLength : new int[] { 0, 12, 16 }) {
        for (int tagLength : new int[] { 0, 4, 12, 16 }) {
          AES_GCM algorithm = AES_GCM.builder().keyLength(keyLength).ivLength(ivLength).tagLength(tagLength).build();
          for (int[] lengths : new int[][] { { keyLength, ivLength }, { keyLength + 1, ivLength }, { keyLength, ivLength + 1 } }) {
            for (int messageLength : new int[] { 0, 17 }) {
              AESEncryptInput encrypt = AESEncryptInput
                .builder()
                .encAlg(algorithm)
                .key(bytes(lengths[0], 1))
                .iv(bytes(lengths[1], 2))
                .msg(bytes(messageLength, 3))
                .aad(bytes(5, 4))
                .build();
              assertSameOutcome("AESEncrypt", encrypt, () -> primitives.AESEncrypt(encrypt));
              decryptCases(algorithm, encrypt);
            }
          }
        }
      }
    }
    assertBothOutcomesSeen("AESEncrypt");
    assertBothOutcomesSeen("AESDecrypt");
  }

  // Decrypts a fresh encryption, then the same with each authenticated part tampered, then with wrong lengths.
  private void decryptCases(AES_GCM algorithm, AESEncryptInput encrypt) {
    AESEncryptOutput sealed;
    try {
      sealed = primitives.AESEncrypt(encrypt);
    } catch (RuntimeException notEncryptable) {
      return;
    }
    List<AESDecryptInput> cases = new ArrayList<>();
    AESDecryptInput valid = AESDecryptInput
      .builder()
      .encAlg(algorithm)
      .key(encrypt.key())
      .iv(encrypt.iv())
      .cipherTxt(sealed.cipherText())
      .authTag(sealed.authTag())
      .aad(encrypt.aad())
      .build();
    cases.add(valid);
    cases.add(valid.toBuilder().aad(bytes(5, 5)).build());
    if (sealed.cipherText().limit() > 0) {
      cases.add(valid.toBuilder().cipherTxt(flipFirstBit(sealed.cipherText())).build());
    }
    if (sealed.authTag().limit() > 0) {
      cases.add(valid.toBuilder().authTag(flipFirstBit(sealed.authTag())).build());
    }
    cases.add(valid.toBuilder().authTag(bytes(sealed.authTag().limit() + 1, 0)).build());
    cases.add(valid.toBuilder().key(bytes(encrypt.key().limit() + 1, 1)).build());
    for (AESDecryptInput decrypt : cases) {
      assertSameOutcome("AESDecrypt", decrypt, () -> primitives.AESDecrypt(decrypt));
    }
  }

  // A JCE failure surfaces as OpaqueError with the JCE exception as obj and as cause.
  @Test
  void aesDecryptFailureKeepsTheCause() {
    AES_GCM algorithm = AES_GCM.builder().keyLength(32).ivLength(12).tagLength(16).build();
    AESEncryptInput encrypt = AESEncryptInput
      .builder()
      .encAlg(algorithm)
      .key(bytes(32, 1))
      .iv(bytes(12, 2))
      .msg(bytes(10, 3))
      .aad(bytes(0, 0))
      .build();
    AESEncryptOutput sealed = primitives.AESEncrypt(encrypt);
    AESDecryptInput tampered = AESDecryptInput
      .builder()
      .encAlg(algorithm)
      .key(encrypt.key())
      .iv(encrypt.iv())
      .cipherTxt(sealed.cipherText())
      .authTag(flipFirstBit(sealed.authTag()))
      .aad(encrypt.aad())
      .build();
    OpaqueError error = assertThrows(OpaqueError.class, () -> primitives.AESDecrypt(tampered));
    assertTrue(error.getCause() instanceof AEADBadTagException, String.valueOf(error.getCause()));
    assertSame(error.getCause(), error.obj());
  }

  @Test
  void generateRandomBytesHasTheRequestedLengthAndVaries() {
    for (int length : new int[] { 0, 1, 32, 1000 }) {
      GenerateRandomBytesInput input = GenerateRandomBytesInput.builder().length(length).build();
      ByteBuffer referenceBytes = (ByteBuffer) ReferenceMpl.call(reference, "GenerateRandomBytes", input);
      assertEquals(referenceBytes.limit(), primitives.GenerateRandomBytes(input).limit());
    }
    GenerateRandomBytesInput input = GenerateRandomBytesInput.builder().length(32).build();
    assertFalse(primitives.GenerateRandomBytes(input).equals(primitives.GenerateRandomBytes(input)));
  }

  @Test
  void rfc5869Vectors() throws IOException {
    for (JsonNode vector : vectors("hkdf-rfc5869.json")) {
      String name = vector.get("name").asText();
      DigestAlgorithm algorithm = DigestAlgorithm.valueOf(vector.get("hash").asText());
      byte[] salt = hex(vector.get("salt"));
      // A.3 has a zero-length salt; the public API spells "no salt" as an absent one.
      ByteBuffer saltInput = salt.length == 0 ? null : ByteBuffer.wrap(salt);
      ByteBuffer prk = primitives.HkdfExtract(
        HkdfExtractInput.builder().digestAlgorithm(algorithm).salt(saltInput).ikm(ByteBuffer.wrap(hex(vector.get("IKM")))).build()
      );
      assertArrayEquals(hex(vector.get("PRK")), prk.array(), name + " PRK");
      ByteBuffer okm = primitives.Hkdf(
        HkdfInput
          .builder()
          .digestAlgorithm(algorithm)
          .salt(saltInput)
          .ikm(ByteBuffer.wrap(hex(vector.get("IKM"))))
          .info(ByteBuffer.wrap(hex(vector.get("info"))))
          .expectedLength(vector.get("L").asInt())
          .build()
      );
      assertArrayEquals(hex(vector.get("OKM")), okm.array(), name + " OKM");
      ByteBuffer expanded = primitives.HkdfExpand(
        HkdfExpandInput
          .builder()
          .digestAlgorithm(algorithm)
          .prk(ByteBuffer.wrap(hex(vector.get("PRK"))))
          .info(ByteBuffer.wrap(hex(vector.get("info"))))
          .expectedLength(vector.get("L").asInt())
          .build()
      );
      assertArrayEquals(hex(vector.get("OKM")), expanded.array(), name + " Expand(PRK)");
    }
  }

  // The client is shared across threads; every thread must get the single-threaded answer.
  @Test
  void concurrentCallsAgree() throws Exception {
    HMacInput hmac = HMacInput.builder().digestAlgorithm(DigestAlgorithm.SHA_384).key(bytes(32, 1)).message(bytes(1000, 2)).build();
    AESEncryptInput aes = AESEncryptInput
      .builder()
      .encAlg(AES_GCM.builder().keyLength(32).ivLength(12).tagLength(16).build())
      .key(bytes(32, 3))
      .iv(bytes(12, 4))
      .msg(bytes(1000, 5))
      .aad(bytes(5, 6))
      .build();
    String expectedHmac = ReferenceMpl.describe(primitives.HMac(hmac));
    String expectedAes = ReferenceMpl.describe(primitives.AESEncrypt(aes));
    java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(8);
    try {
      List<java.util.concurrent.Future<Boolean>> results = new ArrayList<>();
      for (int i = 0; i < 200; i++) {
        results.add(pool.submit(() ->
          expectedHmac.equals(ReferenceMpl.describe(primitives.HMac(hmac))) &&
          expectedAes.equals(ReferenceMpl.describe(primitives.AESEncrypt(aes)))
        ));
      }
      for (java.util.concurrent.Future<Boolean> result : results) {
        assertTrue(result.get());
      }
    } finally {
      pool.shutdown();
    }
  }

  @Test
  void sp800108Vectors() throws IOException {
    JsonNode vectors = vectors("kdf-counter-mode.json");
    for (JsonNode vector : vectors.get("raw")) {
      byte[] okm = KdfCounterMode.derive(
        software.amazon.cryptography.mpl.internal.primitives.DigestAlgorithm.valueOf(vector.get("hash").asText()),
        hex(vector.get("IKM")),
        hex(vector.get("info")),
        vector.get("L").asInt()
      );
      assertArrayEquals(hex(vector.get("OKM")), okm, vector.get("name").asText());
    }
    for (JsonNode vector : vectors.get("public")) {
      ByteBuffer okm = primitives.KdfCounterMode(
        KdfCtrInput
          .builder()
          .digestAlgorithm(DigestAlgorithm.valueOf(vector.get("hash").asText()))
          .ikm(ByteBuffer.wrap(hex(vector.get("IKM"))))
          .expectedLength(vector.get("L").asInt())
          .purpose(ByteBuffer.wrap(hex(vector.get("purpose"))))
          .nonce(ByteBuffer.wrap(hex(vector.get("info"))))
          .build()
      );
      assertArrayEquals(hex(vector.get("OKM")), okm.array(), vector.get("name").asText());
    }
  }

  private static JsonNode vectors(String resource) throws IOException {
    try (InputStream stream = SymmetricPrimitivesTest.class.getResourceAsStream("/vectors/" + resource)) {
      return new ObjectMapper().readTree(stream);
    }
  }

  private static byte[] hex(JsonNode node) {
    String text = node.asText();
    byte[] bytes = new byte[text.length() / 2];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) Integer.parseInt(text.substring(2 * i, 2 * i + 2), 16);
    }
    return bytes;
  }

  private static int hashLength(DigestAlgorithm algorithm) {
    return algorithm == DigestAlgorithm.SHA_256 ? 32 : algorithm == DigestAlgorithm.SHA_384 ? 48 : 64;
  }

  private static ByteBuffer bytes(int length, int seed) {
    byte[] bytes = new byte[length];
    Arrays.fill(bytes, (byte) seed);
    return ByteBuffer.wrap(bytes);
  }

  // A view into the middle of a larger array: arrayOffset is 8, and index 0 is the array's byte 8.
  private static ByteBuffer sliced(int length) {
    ByteBuffer outer = consumed(length + 8);
    outer.position(8);
    ByteBuffer view = outer.slice();
    view.limit(length);
    return view;
  }

  private static ByteBuffer direct(int length) {
    ByteBuffer direct = ByteBuffer.allocateDirect(length);
    direct.put(consumed(length).array());
    direct.position(1);
    return direct;
  }

  // A buffer of distinct bytes whose position is past its first bytes.
  private static ByteBuffer consumed(int length) {
    byte[] bytes = new byte[length];
    for (int i = 0; i < length; i++) {
      bytes[i] = (byte) i;
    }
    ByteBuffer buffer = ByteBuffer.wrap(bytes);
    buffer.position(length / 2);
    return buffer;
  }

  private static ByteBuffer flipFirstBit(ByteBuffer buffer) {
    byte[] bytes = new byte[buffer.limit()];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = buffer.get(i);
    }
    bytes[0] ^= 1;
    return ByteBuffer.wrap(bytes);
  }

  // Also checks that neither library changed the caller's input.
  private String assertSameOutcome(String operation, Object input, Supplier<Object> nativeCall) {
    String before = ReferenceMpl.describe(input);
    String expected = ReferenceMpl.outcome(() -> ReferenceMpl.call(reference, operation, input));
    assertEquals(before, ReferenceMpl.describe(input), operation + ": the reference changed its input");
    String actual = ReferenceMpl.outcome(nativeCall);
    assertEquals(before, ReferenceMpl.describe(input), operation + ": the native library changed its input");
    assertEquals(expected, actual, operation + " on " + before);
    outcomes.merge(operation + (actual.startsWith("throws") ? " throws" : " returns"), 1, Integer::sum);
    return actual;
  }

  // Guards against a vacuous run in which every case succeeds or every case fails.
  private void assertBothOutcomesSeen(String operation) {
    assertTrue(outcomes.containsKey(operation + " returns"), operation + " never succeeded: " + outcomes);
    assertTrue(outcomes.containsKey(operation + " throws"), operation + " never failed: " + outcomes);
  }
}
