// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.vectors;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import software.amazon.cryptography.materialproviders.exceptions.MaterialProvidersException;
import software.amazon.cryptography.materialproviders.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.materialproviders.vectors.TestVectors.DecryptKind;
import software.amazon.cryptography.materialproviders.vectors.TestVectors.DecryptVector;
import software.amazon.cryptography.materialproviders.vectors.TestVectors.EncryptKind;
import software.amazon.cryptography.materialproviders.vectors.TestVectors.EncryptVector;

/**
 * TestManifests.dfy for any number of sides: each side runs every encrypt vector (TestEncrypts), and then every side
 * runs the decrypt vectors each side produced (TestDecrypts), so the native MPL decrypts what the Dafny-based MPL
 * encrypted and the other way round. Positive and negative outcomes are checked as TestVectors.dfy checks them;
 * in addition a failing vector must fail with the same message on both sides, given the same input.
 */
final class VectorRunner {

  /** Counts per row: run, passed, skipped. */
  final Map<String, int[]> counts = new TreeMap<>();
  final Map<String, Integer> skipReasons = new TreeMap<>();
  final List<String> failures = new ArrayList<>();
  private final List<Side> sides;
  // Failure messages of one input, by side, to compare across sides.
  private final Map<String, Map<String, String>> failureMessages = new LinkedHashMap<>();

  VectorRunner(Side... sides) {
    this.sides = Arrays.asList(sides);
  }

  /** Runs an encrypt manifest's tests object, then the decrypt vectors made from it. */
  void runEncryptManifest(String manifest, JsonNode tests) {
    List<EncryptVector> vectors = new ArrayList<>();
    tests
      .fields()
      .forEachRemaining(test -> {
        try {
          vectors.add(EncryptVector.parse(test.getKey(), test.getValue()));
        } catch (VectorException e) {
          skip(manifest + " encrypt " + rawType(test.getValue()), "the Dafny runner rejects this vector: " + e.getMessage());
        }
      });
    runEncryptVectors(manifest, vectors);
  }

  void runEncryptVectors(String manifest, List<EncryptVector> vectors) {
    Map<Side, List<DecryptVector>> produced = new LinkedHashMap<>();
    for (Side side : sides) {
      List<DecryptVector> decryptVectors = new ArrayList<>();
      for (EncryptVector vector : vectors) {
        DecryptVector decrypt = encrypt(manifest, side, vector);
        if (decrypt != null) {
          // The decrypt manifest is written and read back.
          decryptVectors.add(DecryptVector.parse(decrypt.name, Json.roundTrip(decrypt.toJson())));
        }
      }
      produced.put(side, decryptVectors);
    }
    for (Map.Entry<Side, List<DecryptVector>> entry : produced.entrySet()) {
      for (Side side : sides) {
        for (DecryptVector vector : entry.getValue()) {
          decrypt(manifest + " decrypt " + entry.getKey().name() + "->" + side.name(), entry.getKey().name(), side, vector);
        }
      }
    }
    compareFailureMessages();
  }

  /** Runs a decrypt manifest's tests object on every side. */
  void runDecryptManifest(String manifest, JsonNode tests) {
    List<DecryptVector> vectors = new ArrayList<>();
    tests
      .fields()
      .forEachRemaining(test -> {
        try {
          vectors.add(DecryptVector.parse(test.getKey(), test.getValue()));
        } catch (VectorException e) {
          skip(manifest + " decrypt " + rawType(test.getValue()), "the Dafny runner rejects this vector: " + e.getMessage());
        }
      });
    for (Side side : sides) {
      for (DecryptVector vector : vectors) {
        decrypt(manifest + " decrypt " + side.name(), "manifest", side, vector);
      }
    }
    compareFailureMessages();
  }

  // TestGetEncryptionMaterials; returns the decrypt vector of a successful encrypt, as ToDecryptTestVectors makes it.
  private DecryptVector encrypt(String manifest, Side side, EncryptVector vector) {
    String row = manifest + " encrypt " + side.name() + " " + vector.kind.type + " " + label(vector.encryptDescription);
    Side.Cmm cmm;
    try {
      cmm = side.cmm(vector.encryptDescription);
    } catch (Side.Skipped e) {
      skip(row, e.getMessage());
      return null;
    } catch (RuntimeException e) {
      fail(row, vector.name, "building the CMM failed: " + e);
      return null;
    }
    Side.Encrypted materials;
    try {
      materials = cmm.getEncryptionMaterials(vector);
    } catch (RuntimeException e) {
      if (vector.kind == EncryptKind.NEGATIVE_ENCRYPT && isLibraryFailure(side, e)) {
        pass(row);
        failureMessages.computeIfAbsent("encrypt " + vector.name + " " + vector.toJson(), k -> new TreeMap<>()).put(side.name(), message(e));
      } else {
        fail(row, vector.name, "GetEncryptionMaterials failed: " + e);
      }
      return null;
    }
    if (vector.kind == EncryptKind.NEGATIVE_ENCRYPT) {
      fail(row, vector.name, "GetEncryptionMaterials succeeded; expected: " + vector.errorDescription);
      return null;
    }
    pass(row);
    return vector.toDecryptVector(materials);
  }

  // TestDecryptMaterials.
  private void decrypt(String rowPrefix, String producer, Side side, DecryptVector vector) {
    String row = rowPrefix + " " + vector.kind.type + " " + label(vector.keyDescription);
    Side.Cmm cmm;
    try {
      cmm = side.cmm(vector.keyDescription);
    } catch (Side.Skipped e) {
      skip(row, e.getMessage());
      return;
    } catch (RuntimeException e) {
      fail(row, vector.name, "building the CMM failed: " + e);
      return;
    }
    Side.Decrypted result;
    try {
      result = cmm.decryptMaterials(vector);
    } catch (RuntimeException e) {
      if (vector.kind == DecryptKind.NEGATIVE && isLibraryFailure(side, e)) {
        pass(row);
        failureMessages
          .computeIfAbsent("decrypt " + producer + " " + vector.name + " " + vector.toJson(), k -> new TreeMap<>())
          .put(side.name(), message(e));
      } else {
        fail(row, vector.name, "DecryptMaterials failed: " + e);
      }
      return;
    }
    if (vector.kind == DecryptKind.NEGATIVE) {
      fail(row, vector.name, "DecryptMaterials succeeded; expected: " + vector.errorDescription);
      return;
    }
    List<String> mismatches = new ArrayList<>();
    if (!Arrays.equals(vector.expected.plaintextDataKey, result.plaintextDataKey)) {
      mismatches.add("plaintextDataKey does not match");
    }
    if (!Arrays.equals(vector.expected.symmetricSigningKey, result.symmetricSigningKey)) {
      mismatches.add("symmetricSigningKey does not match");
    }
    if (!sorted(vector.expected.requiredEncryptionContextKeys).equals(sorted(result.requiredEncryptionContextKeys))) {
      mismatches.add(
        "requiredEncryptionContextKeys does not match: expected " + vector.expected.requiredEncryptionContextKeys + ", got " +
        result.requiredEncryptionContextKeys
      );
    }
    if (mismatches.isEmpty()) {
      pass(row);
    } else {
      fail(row, vector.name, String.join("; ", mismatches));
    }
  }

  /**
   * Native and reference messages that differ by design. The static keyring for "no-plaintext-data-key" returns
   * encrypted data keys without a plaintext data key: the reference CMM rejects that result, while the native
   * materials API cannot hold such materials, so the keyring's own attempt to add the key fails first.
   */
  private static final Map<String, String> KNOWN_DIFFERENCES = Collections.singletonMap(
    "Adding encrypted data keys without a plaintext data key is not allowed.",
    "Could not retrieve materials required for encryption"
  );

  /** How often each known difference was seen, by native message. */
  final Map<String, Integer> knownDifferences = new TreeMap<>();

  // The same failing input fails with the same message on every side that ran it.
  private void compareFailureMessages() {
    for (Map.Entry<String, Map<String, String>> entry : failureMessages.entrySet()) {
      Map<String, String> messages = entry.getValue();
      if (messages.size() < 2 || messages.values().stream().distinct().count() == 1) {
        continue;
      }
      String nativeMessage = messages.get("native");
      if (nativeMessage != null && messages.size() == 2 && messages.get("reference").equals(KNOWN_DIFFERENCES.get(nativeMessage))) {
        knownDifferences.merge(nativeMessage, 1, Integer::sum);
      } else {
        failures.add("failure messages differ for " + entry.getKey() + ": " + messages);
      }
    }
    failureMessages.clear();
  }

  // Native failures must be the library's exceptions; the reference reports every failure as its own error types.
  private static boolean isLibraryFailure(Side side, RuntimeException e) {
    return !(side instanceof NativeSide) || e instanceof MaterialProvidersException;
  }

  private static final String LIST_MARKER = " String representation of Exceptions in list.";

  /**
   * A failure's message and, for a list of failures, each one's message, in order. The Dafny Java boundary appends
   * the list to a CollectionOfErrors message; the native exception keeps it in {@code failures()}.
   */
  static String message(Throwable e) {
    String message = String.valueOf(e.getMessage());
    List<String> inner = new ArrayList<>();
    if (e instanceof NoMatchingDataKeyException) {
      ((NoMatchingDataKeyException) e).failures().forEach(f -> inner.add(message(f)));
    } else if (e.getClass().getSimpleName().equals("CollectionOfErrors")) {
      int marker = message.indexOf(LIST_MARKER);
      message = marker < 0 ? message : message.substring(0, marker);
      try {
        for (Object f : (List<?>) e.getClass().getMethod("list").invoke(e)) {
          inner.add(message((Throwable) f));
        }
      } catch (ReflectiveOperationException r) {
        throw new IllegalStateException(r);
      }
    }
    return inner.isEmpty() ? message : message + " " + inner;
  }

  /** The row label of a description: its kind, with a CMM's underlying kind. */
  static String label(KeyDescription description) {
    if (description instanceof KeyDescription.RequiredEncryptionContext) {
      return description.kind() + "(" + label(((KeyDescription.RequiredEncryptionContext) description).underlying) + ")";
    }
    return description.kind();
  }

  private static String rawType(JsonNode test) {
    JsonNode description = test.has("encryptKeyDescription") ? test.get("encryptKeyDescription") : test.get("keyDescription");
    String type = test.path("type").asText("?");
    return type + " " + (description == null ? "?" : description.path("type").asText("?"));
  }

  private static List<String> sorted(List<String> keys) {
    List<String> sorted = new ArrayList<>(keys);
    Collections.sort(sorted);
    return sorted;
  }

  private void pass(String row) {
    int[] count = row(row);
    count[0]++;
    count[1]++;
  }

  private void fail(String row, String vector, String why) {
    row(row)[0]++;
    failures.add(row + " [" + vector + "]: " + why);
  }

  private void skip(String row, String reason) {
    row(row)[2]++;
    skipReasons.merge(row + ": " + reason, 1, Integer::sum);
  }

  private int[] row(String row) {
    return counts.computeIfAbsent(row, r -> new int[3]);
  }

  /** The counts as a table: row, run, passed, skipped. */
  String report() {
    StringBuilder report = new StringBuilder(String.format("%-110s %6s %6s %7s%n", "vectors", "run", "passed", "skipped"));
    int[] total = new int[3];
    for (Map.Entry<String, int[]> entry : counts.entrySet()) {
      int[] c = entry.getValue();
      report.append(String.format("%-110s %6d %6d %7d%n", entry.getKey(), c[0], c[1], c[2]));
      for (int i = 0; i < 3; i++) {
        total[i] += c[i];
      }
    }
    report.append(String.format("%-110s %6d %6d %7d%n", "total", total[0], total[1], total[2]));
    report.append("skip reasons:\n");
    skipReasons.forEach((reason, n) -> report.append("  ").append(n).append(" x ").append(reason).append('\n'));
    report.append("known message differences:\n");
    knownDifferences.forEach((message, n) -> report.append("  ").append(n).append(" x ").append(message).append('\n'));
    report.append("failures: ").append(failures.size()).append('\n');
    failures.forEach(f -> report.append("  ").append(f).append('\n'));
    return report.toString();
  }
}
