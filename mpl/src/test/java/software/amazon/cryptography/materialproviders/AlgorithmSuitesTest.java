// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteInfo;
import software.amazon.cryptography.materialproviders.model.DBEAlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.DIRECT_KEY_WRAPPING;
import software.amazon.cryptography.materialproviders.model.DerivationAlgorithm;
import software.amazon.cryptography.materialproviders.model.ESDKAlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.EdkWrappingAlgorithm;
import software.amazon.cryptography.materialproviders.model.Encrypt;
import software.amazon.cryptography.materialproviders.model.HKDF;
import software.amazon.cryptography.materialproviders.model.IDENTITY;
import software.amazon.cryptography.materialproviders.model.IntermediateKeyWrapping;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;
import software.amazon.cryptography.materialproviders.model.None;
import software.amazon.cryptography.materialproviders.model.SignatureAlgorithm;
import software.amazon.cryptography.materialproviders.model.SymmetricSignatureAlgorithm;
import software.amazon.cryptography.primitives.model.AES_GCM;
import software.amazon.cryptography.primitives.model.DigestAlgorithm;

// Differential tests against the published Dafny-based MPL:
// every case runs on both libraries and must produce the same result or the same exception and message.
class AlgorithmSuitesTest {

  private final MaterialProviders mpl = MaterialProviders
    .builder()
    .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
    .build();
  private final Object reference = ReferenceMpl.materialProviders();

  @Test
  void getAlgorithmSuiteInfoMatchesReferenceForEveryTwoByteId() {
    int found = 0;
    for (int id = 0; id <= 0xFFFF; id++) {
      String nativeOutcome = assertSameOutcome(
        "GetAlgorithmSuiteInfo",
        new byte[] { (byte) (id >> 8), (byte) id }
      );
      if (!nativeOutcome.startsWith("throws")) {
        found++;
      }
    }
    assertEquals(13, found, "number of supported binary ids");
  }

  @Test
  void getAlgorithmSuiteInfoMatchesReferenceForOtherLengths() {
    assertSameOutcome("GetAlgorithmSuiteInfo", new byte[0]);
    assertSameOutcome("GetAlgorithmSuiteInfo", new byte[] { 0x01 });
    assertSameOutcome("GetAlgorithmSuiteInfo", new byte[] { 0x01, 0x78, 0x00 });
  }

  // The Dafny-based MPL reads ByteBuffer inputs as bytes [0, limit), ignoring position.
  @Test
  void getAlgorithmSuiteInfoReadsFromZeroToLimit() {
    ByteBuffer consumed = ByteBuffer.wrap(new byte[] { 0x01, 0x78 });
    consumed.get();
    assertSameOutcome("GetAlgorithmSuiteInfo", consumed);

    // wrap(array, offset, length) leaves the bytes before offset inside [0, limit).
    ByteBuffer offset = ByteBuffer.wrap(new byte[] { 0x00, 0x01, 0x78 }, 1, 2);
    assertSameOutcome("GetAlgorithmSuiteInfo", offset);

    ByteBuffer truncated = ByteBuffer.wrap(new byte[] { 0x01, 0x78, 0x00 });
    truncated.limit(2);
    assertSameOutcome("GetAlgorithmSuiteInfo", truncated);

    ByteBuffer direct = ByteBuffer.allocateDirect(2).put((byte) 0x05).put((byte) 0x78);
    assertSameOutcome("GetAlgorithmSuiteInfo", direct);
    assertEquals(2, direct.position(), "input buffer position is left unchanged");
  }

  @Test
  void getAlgorithmSuiteInfoMatchesReferenceForNullSlicedAndReadOnlyBuffers() {
    assertSameOutcome("GetAlgorithmSuiteInfo", (Object) null);
    ByteBuffer sliced = ByteBuffer.wrap(new byte[] { 0x00, 0x05, 0x78 });
    sliced.position(1);
    assertSameOutcome("GetAlgorithmSuiteInfo", sliced.slice());
    assertSameOutcome("GetAlgorithmSuiteInfo", ByteBuffer.wrap(new byte[] { 0x05, 0x78 }).asReadOnlyBuffer());
    assertSameOutcome("ValidAlgorithmSuiteInfo", (Object) null);
  }

  @Test
  void getAlgorithmSuiteInfoReturnsIndependentBuffers() {
    AlgorithmSuiteInfo first = mpl.GetAlgorithmSuiteInfo(ByteBuffer.wrap(new byte[] { 0x05, 0x78 }));
    first.binaryId().put(0, (byte) 0x7F);
    AlgorithmSuiteInfo second = mpl.GetAlgorithmSuiteInfo(ByteBuffer.wrap(new byte[] { 0x05, 0x78 }));
    assertEquals(0x05, second.binaryId().get(0));
  }

  @Test
  void validAlgorithmSuiteInfoMatchesReferenceForEverySuiteAndFieldSubstitution() {
    List<AlgorithmSuiteInfo> suites = supportedSuites();
    Map<String, Function<AlgorithmSuiteInfo.Builder, AlgorithmSuiteInfo.Builder>> substitutions =
      substitutions(suites);
    int accepted = 0;
    int cases = 0;
    for (AlgorithmSuiteInfo suite : suites) {
      assertEquals("void", nativeOutcome("ValidAlgorithmSuiteInfo", suite), "suite from GetAlgorithmSuiteInfo is valid");
      for (Map.Entry<String, Function<AlgorithmSuiteInfo.Builder, AlgorithmSuiteInfo.Builder>> substitution : substitutions.entrySet()) {
        AlgorithmSuiteInfo candidate = substitution.getValue().apply(suite.toBuilder()).build();
        String outcome = assertSameOutcome("ValidAlgorithmSuiteInfo", candidate);
        cases++;
        if (outcome.equals("void")) {
          accepted++;
        }
      }
    }
    // Guards against a vacuous run in which every case is accepted or every case is rejected.
    assertTrue(accepted > suites.size(), "some substitutions keep a suite valid: " + accepted);
    assertTrue(accepted < cases, "some substitutions make a suite invalid: " + accepted + "/" + cases);
  }

  private List<AlgorithmSuiteInfo> supportedSuites() {
    List<AlgorithmSuiteInfo> suites = new ArrayList<>();
    for (int id = 0; id <= 0xFFFF; id++) {
      try {
        suites.add(mpl.GetAlgorithmSuiteInfo(ByteBuffer.wrap(new byte[] { (byte) (id >> 8), (byte) id })));
      } catch (RuntimeException unsupported) {
        // Most ids name no suite.
      }
    }
    return suites;
  }

  // Each entry replaces one field with a value it takes in some supported suite, or an off-table value.
  private static Map<String, Function<AlgorithmSuiteInfo.Builder, AlgorithmSuiteInfo.Builder>> substitutions(
    List<AlgorithmSuiteInfo> suites
  ) {
    Map<String, Function<AlgorithmSuiteInfo.Builder, AlgorithmSuiteInfo.Builder>> substitutions = new LinkedHashMap<>();
    for (ESDKAlgorithmSuiteId id : ESDKAlgorithmSuiteId.values()) {
      substitutions.put("id " + id, b -> b.id(AlgorithmSuiteId.builder().ESDK(id).build()));
    }
    for (DBEAlgorithmSuiteId id : DBEAlgorithmSuiteId.values()) {
      substitutions.put("id " + id, b -> b.id(AlgorithmSuiteId.builder().DBE(id).build()));
    }
    for (AlgorithmSuiteInfo suite : suites) {
      String name = ReferenceMpl.describe(suite.binaryId());
      substitutions.put("binaryId of " + name, b -> b.binaryId(suite.binaryId()));
      substitutions.put("kdf of " + name, b -> b.kdf(suite.kdf()));
      substitutions.put("commitment of " + name, b -> b.commitment(suite.commitment()));
      substitutions.put("signature of " + name, b -> b.signature(suite.signature()));
      substitutions.put("symmetricSignature of " + name, b -> b.symmetricSignature(suite.symmetricSignature()));
      substitutions.put("edkWrapping of " + name, b -> b.edkWrapping(suite.edkWrapping()));
      substitutions.put("encrypt of " + name, b -> b.encrypt(suite.encrypt()));
    }
    substitutions.put("binaryId 0x0000", b -> b.binaryId(ByteBuffer.wrap(new byte[2])));
    substitutions.put("binaryId with trailing byte", b -> b.binaryId(ByteBuffer.wrap(new byte[] { 0x05, 0x78, 0x00 })));
    for (int version = 0; version <= 3; version++) {
      int messageVersion = version;
      substitutions.put("messageVersion " + version, b -> b.messageVersion(messageVersion));
    }
    substitutions.put("encrypt tag 12", b -> b.encrypt(aesGcm(32, 12, 12)));
    substitutions.put("encrypt iv 16", b -> b.encrypt(aesGcm(32, 16, 16)));
    substitutions.put("kdf IDENTITY", b -> b.kdf(identity()));
    substitutions.put("kdf None", b -> b.kdf(none()));
    substitutions.put("commitment IDENTITY", b -> b.commitment(identity()));
    for (DigestAlgorithm hmac : DigestAlgorithm.values()) {
      for (int salt : new int[] { 0, 32 }) {
        for (int length : new int[] { 16, 24, 32 }) {
          String label = hmac + " salt " + salt + " length " + length;
          substitutions.put("kdf HKDF " + label, b -> b.kdf(hkdf(hmac, salt, length, length)));
          substitutions.put("commitment HKDF " + label, b -> b.commitment(hkdf(hmac, salt, length, length)));
        }
      }
      substitutions.put("kdf HKDF " + hmac + " input differs from output", b -> b.kdf(hkdf(hmac, 32, 16, 32)));
      substitutions.put(
        "symmetricSignature HMAC " + hmac,
        b -> b.symmetricSignature(SymmetricSignatureAlgorithm.builder().HMAC(hmac).build())
      );
    }
    DerivationAlgorithm sha512 = hkdf(DigestAlgorithm.SHA_512, 32, 32, 32);
    DerivationAlgorithm sha256 = hkdf(DigestAlgorithm.SHA_256, 0, 32, 32);
    substitutions.put("edkWrapping intermediate with SHA-256 kdfs", b -> b.edkWrapping(intermediate(sha256, sha256, aesGcm(32, 16, 12))));
    substitutions.put("edkWrapping intermediate with SHA-256 mac kdf", b -> b.edkWrapping(intermediate(sha512, sha256, aesGcm(32, 16, 12))));
    substitutions.put("edkWrapping intermediate with SHA-256 key kdf", b -> b.edkWrapping(intermediate(sha256, sha512, aesGcm(32, 16, 12))));
    substitutions.put("edkWrapping intermediate with AES-128", b -> b.edkWrapping(intermediate(sha512, sha512, aesGcm(16, 16, 12))));
    substitutions.put(
      "edkWrapping direct",
      b -> b.edkWrapping(EdkWrappingAlgorithm.builder().DIRECT_KEY_WRAPPING(DIRECT_KEY_WRAPPING.builder().build()).build())
    );
    substitutions.put("signature None", b -> b.signature(SignatureAlgorithm.builder().None(None.builder().build()).build()));
    return substitutions;
  }

  private static Encrypt aesGcm(int keyLength, int tagLength, int ivLength) {
    return Encrypt
      .builder()
      .AES_GCM(AES_GCM.builder().keyLength(keyLength).tagLength(tagLength).ivLength(ivLength).build())
      .build();
  }

  private static DerivationAlgorithm hkdf(DigestAlgorithm hmac, int salt, int input, int output) {
    return DerivationAlgorithm
      .builder()
      .HKDF(HKDF.builder().hmac(hmac).saltLength(salt).inputKeyLength(input).outputKeyLength(output).build())
      .build();
  }

  private static DerivationAlgorithm identity() {
    return DerivationAlgorithm.builder().IDENTITY(IDENTITY.builder().build()).build();
  }

  private static DerivationAlgorithm none() {
    return DerivationAlgorithm.builder().None(None.builder().build()).build();
  }

  private static EdkWrappingAlgorithm intermediate(
    DerivationAlgorithm keyEncryptionKeyKdf,
    DerivationAlgorithm macKeyKdf,
    Encrypt pdkEncrypt
  ) {
    return EdkWrappingAlgorithm
      .builder()
      .IntermediateKeyWrapping(
        IntermediateKeyWrapping
          .builder()
          .keyEncryptionKeyKdf(keyEncryptionKeyKdf)
          .macKeyKdf(macKeyKdf)
          .pdkEncryptAlgorithm(pdkEncrypt)
          .build()
      )
      .build();
  }

  private String assertSameOutcome(String operation, byte[] binaryId) {
    return assertSameOutcome(operation, ByteBuffer.wrap(binaryId));
  }

  // Runs the operation on both libraries and returns the native outcome.
  private String assertSameOutcome(String operation, Object input) {
    String expected = ReferenceMpl.outcome(() -> ReferenceMpl.call(reference, operation, input));
    String actual = nativeOutcome(operation, input);
    assertEquals(expected, actual, operation + " on " + ReferenceMpl.describe(input));
    return actual;
  }

  private String nativeOutcome(String operation, Object input) {
    return ReferenceMpl.outcome(() -> {
      if (operation.equals("GetAlgorithmSuiteInfo")) {
        return mpl.GetAlgorithmSuiteInfo((ByteBuffer) input);
      }
      mpl.ValidAlgorithmSuiteInfo((AlgorithmSuiteInfo) input);
      return null;
    });
  }
}
