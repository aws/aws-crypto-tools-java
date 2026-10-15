// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.vectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The MPL's own test vectors (TestVectorsAwsCryptographicMaterialProviders at MPL main a7be0b938), run against the
 * native MPL's public API and, with the same runner, against the published Dafny-based MPL; each side also decrypts
 * what the other encrypted. Resources under {@code vectors/mpl}:
 * <ul>
 *   <li>{@code keys.json}: the keys manifest the vectors name;</li>
 *   <li>{@code legacy-test.json}: the encrypt manifest checked in beside it (written by an earlier runner version; its
 *       {@code caching-cmm} vectors use a key description type the current runner rejects);</li>
 *   <li>{@code decrypt-manifest.json}: a decrypt manifest written by the Dafny MPL, with fixed encrypted data keys.</li>
 * </ul>
 * The generated vectors are CompleteVectors' in-code set, which is what CI writes as the encrypt manifest.
 */
class MplTestVectorsTest {

  private static final Map<String, KeyMaterial> KEYS = keys();

  private static Map<String, KeyMaterial> keys() {
    JsonNode manifest = Json.resource("/vectors/mpl/keys.json");
    assertEquals("keys", manifest.path("manifest").path("type").asText());
    return KeyMaterial.parseKeys(manifest);
  }

  @Test
  void generatedVectors() {
    List<TestVectors.EncryptVector> vectors = new ArrayList<>();
    int i = 0;
    for (TestVectors.EncryptVector vector : CompleteVectors.all()) {
      // WriteStuff names each vector by a UUID and StartEncrypt reads the manifest back.
      vectors.add(TestVectors.EncryptVector.parse("generated-" + i++, Json.roundTrip(vector.toJson())));
    }
    VectorRunner runner = run(r -> r.runEncryptVectors("generated", vectors));
    assertEquals(EXPECTED_GENERATED, vectors.size(), "generated vectors");
    assertOnlyKmsAsymmetricSkipped(runner);
    // 2 sides x (1559 - 94 KMS RSA/ECDH) encrypts, then 4 side pairs x 1465 decrypts; 2 x 94 skipped.
    assertTotals(runner, 8786, 188);
  }

  @Test
  void legacyManifest() {
    JsonNode manifest = Json.resource("/vectors/mpl/legacy-test.json");
    VectorRunner runner = run(r -> r.runEncryptManifest("legacy", manifest.get("tests")));
    for (String reason : runner.skipReasons.keySet()) {
      assertTrue(
        reason.contains(NativeSide.KMS_ASYMMETRIC_SKIP) || reason.contains("Unsupported KeyDescription type:caching-cmm"),
        reason
      );
    }
    // 1075 vectors: 733 caching-cmm rejected at parse; 2 sides x 26 KMS RSA skipped.
    assertTotals(runner, 1888, 785);
  }

  @Test
  void fixedDecryptManifest() {
    JsonNode manifest = Json.resource("/vectors/mpl/decrypt-manifest.json");
    // GetManifest.
    assertEquals("awses-mpl-decrypt", manifest.path("manifest").path("type").asText());
    assertEquals("file://keys.json", manifest.path("keys").asText());
    VectorRunner runner = run(r -> r.runDecryptManifest("fixed", manifest.get("tests")));
    assertTrue(runner.skipReasons.isEmpty(), runner.skipReasons::toString);
    assertTotals(runner, 2, 0);
  }

  private static final int EXPECTED_GENERATED = 1559;

  private static VectorRunner run(java.util.function.Consumer<VectorRunner> body) {
    try (VectorEnvironment env = new VectorEnvironment(KEYS)) {
      VectorRunner runner = new VectorRunner(new NativeSide(env), new ReferenceSide(env));
      body.accept(runner);
      String report = runner.report();
      System.out.println(report);
      assertTrue(runner.failures.isEmpty(), report);
      assertTrue(runner.counts.values().stream().anyMatch(c -> c[1] > 0), "nothing ran");
      return runner;
    }
  }

  private static void assertTotals(VectorRunner runner, int run, int skipped) {
    int[] total = new int[3];
    for (int[] c : runner.counts.values()) {
      for (int i = 0; i < 3; i++) {
        total[i] += c[i];
      }
    }
    assertEquals(run, total[0], "run");
    assertEquals(run, total[1], "passed");
    assertEquals(skipped, total[2], "skipped");
  }

  private static void assertOnlyKmsAsymmetricSkipped(VectorRunner runner) {
    for (String reason : runner.skipReasons.keySet()) {
      assertTrue(reason.contains(NativeSide.KMS_ASYMMETRIC_SKIP), reason);
    }
  }
}
