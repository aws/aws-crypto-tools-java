// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.vectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.AllSuites;
import software.amazon.cryptography.materialproviders.CommitmentPolicy;
import software.amazon.cryptography.materialproviders.DbeCommitmentPolicy;
import software.amazon.cryptography.materialproviders.EsdkCommitmentPolicy;

/**
 * The encrypt and decrypt test vectors of TestVectors.dfy, read as ParseJsonManifests.dfy does and written as
 * WriteJsonManifests.dfy does.
 */
final class TestVectors {

  private TestVectors() {}

  enum EncryptKind {
    POSITIVE("positive-keyring"),
    NEGATIVE_DECRYPT("negative-decrypt-keyring"),
    NEGATIVE_ENCRYPT("negative-encrypt-keyring");

    final String type;

    EncryptKind(String type) {
      this.type = type;
    }
  }

  enum DecryptKind {
    POSITIVE("positive-keyring"),
    NEGATIVE("negative-keyring");

    final String type;

    DecryptKind(String type) {
      this.type = type;
    }
  }

  static final class Edk {

    final String keyProviderId;
    final byte[] keyProviderInfo;
    final byte[] ciphertext;

    Edk(String keyProviderId, byte[] keyProviderInfo, byte[] ciphertext) {
      this.keyProviderId = keyProviderId;
      this.keyProviderInfo = keyProviderInfo.clone();
      this.ciphertext = ciphertext.clone();
    }

    static Edk parse(JsonNode json) {
      return new Edk(
        Json.getString("keyProviderId", json),
        Json.base64(Json.getString("keyProviderInfo", json)),
        Json.base64(Json.getString("ciphertext", json))
      );
    }

    ObjectNode toJson() {
      return Json.NODES
        .objectNode()
        .put("keyProviderId", keyProviderId)
        .put("keyProviderInfo", Json.base64(keyProviderInfo))
        .put("ciphertext", Json.base64(ciphertext));
    }
  }

  /** EncryptTestVector: the three cases share every field; unused ones are null. */
  static final class EncryptVector {

    final EncryptKind kind;
    final String name;
    final Optional<String> description;
    final Map<String, String> encryptionContext;
    final AlgorithmSuite algorithmSuite;
    final OptionalLong maxPlaintextLength;
    /** Null when absent. */
    final List<String> requiredEncryptionContextKeys;
    /** Null when absent. */
    final Map<String, String> reproducedEncryptionContext;
    /** The key description of POSITIVE and NEGATIVE_DECRYPT; NEGATIVE_ENCRYPT's single description. */
    final KeyDescription encryptDescription;
    /** Null for NEGATIVE_ENCRYPT. */
    final KeyDescription decryptDescription;
    /** errorDescription or decryptErrorDescription; null for POSITIVE. */
    final String errorDescription;

    EncryptVector(
      EncryptKind kind,
      String name,
      Optional<String> description,
      Map<String, String> encryptionContext,
      AlgorithmSuite algorithmSuite,
      OptionalLong maxPlaintextLength,
      List<String> requiredEncryptionContextKeys,
      Map<String, String> reproducedEncryptionContext,
      KeyDescription encryptDescription,
      KeyDescription decryptDescription,
      String errorDescription
    ) {
      this.kind = kind;
      this.name = name;
      this.description = description;
      this.encryptionContext = Collections.unmodifiableMap(new LinkedHashMap<>(encryptionContext));
      this.algorithmSuite = algorithmSuite;
      this.maxPlaintextLength = maxPlaintextLength;
      this.requiredEncryptionContextKeys = requiredEncryptionContextKeys == null
        ? null
        : Collections.unmodifiableList(new ArrayList<>(requiredEncryptionContextKeys));
      this.reproducedEncryptionContext = reproducedEncryptionContext == null
        ? null
        : Collections.unmodifiableMap(new LinkedHashMap<>(reproducedEncryptionContext));
      this.encryptDescription = encryptDescription;
      this.decryptDescription = decryptDescription;
      this.errorDescription = errorDescription;
    }

    /** A generated vector, without a description (CompleteVectors). */
    static EncryptVector generated(
      EncryptKind kind,
      String name,
      Map<String, String> encryptionContext,
      AlgorithmSuite algorithmSuite,
      List<String> requiredEncryptionContextKeys,
      Map<String, String> reproducedEncryptionContext,
      KeyDescription encryptDescription,
      KeyDescription decryptDescription,
      String errorDescription
    ) {
      return new EncryptVector(
        kind,
        name,
        Optional.empty(),
        encryptionContext,
        algorithmSuite,
        OptionalLong.empty(),
        requiredEncryptionContextKeys,
        reproducedEncryptionContext,
        encryptDescription,
        decryptDescription,
        errorDescription
      );
    }

    CommitmentPolicy commitmentPolicy() {
      return compatibleCommitmentPolicy(algorithmSuite);
    }

    /** EncryptTestVectorToJson. */
    ObjectNode toJson() {
      String id = hex(algorithmSuite);
      ObjectNode json = Json.NODES.objectNode().put("type", kind.type).put("description", name + " " + id);
      if (kind != EncryptKind.POSITIVE) {
        json.put(kind == EncryptKind.NEGATIVE_ENCRYPT ? "errorDescription" : "decryptErrorDescription", errorDescription);
      }
      json.put("algorithmSuiteId", id);
      if (kind == EncryptKind.NEGATIVE_ENCRYPT) {
        json.set("keyDescription", encryptDescription.toJson());
      } else {
        json.set("encryptKeyDescription", encryptDescription.toJson());
        json.set("decryptKeyDescription", decryptDescription.toJson());
      }
      if (kind != EncryptKind.NEGATIVE_ENCRYPT && reproducedEncryptionContext != null) {
        json.set("reproducedEncryptionContext", Json.stringMap(reproducedEncryptionContext));
      }
      if (maxPlaintextLength.isPresent()) {
        json.put("maxPlaintextLength", maxPlaintextLength.getAsLong());
      }
      if (requiredEncryptionContextKeys != null) {
        json.set("requiredEncryptionContextKeys", Json.strings(requiredEncryptionContextKeys));
      }
      json.set("encryptionContext", Json.stringMap(encryptionContext));
      return json;
    }

    /** ToEncryptTestVector. */
    static EncryptVector parse(String name, JsonNode json) {
      Json.object(json, "EncryptTestVector");
      String type = Json.getString("type", json);
      Optional<String> description = optionalString("description", json);
      Map<String, String> encryptionContext = Json.stringMap("encryptionContext", json);
      AlgorithmSuite suite = algorithmSuite(json);
      List<String> required = requiredEncryptionContextKeys(json);
      Map<String, String> reproduced = Json.optionalStringMap("reproducedEncryptionContext", json).orElse(null);
      // GetPositiveLong(...).ToOption(): a value that is not a positive int64 means none.
      OptionalLong maxPlaintextLength;
      try {
        maxPlaintextLength = OptionalLong.of(Json.getNat("maxPlaintextLength", json));
      } catch (VectorException e) {
        maxPlaintextLength = OptionalLong.empty();
      }
      switch (type) {
        case "positive-keyring":
          return new EncryptVector(
            EncryptKind.POSITIVE,
            name,
            description,
            encryptionContext,
            suite,
            maxPlaintextLength,
            required,
            reproduced,
            KeyDescription.parse(Json.get("encryptKeyDescription", json)),
            KeyDescription.parse(Json.get("decryptKeyDescription", json)),
            null
          );
        case "negative-encrypt-keyring":
          {
            KeyDescription keyDescription = KeyDescription.parse(Json.get("keyDescription", json));
            String error = Json.getString("errorDescription", json);
            if (reproduced != null) {
              throw new VectorException("reproducedEncryptionContext not supported");
            }
            return new EncryptVector(
              EncryptKind.NEGATIVE_ENCRYPT,
              name,
              description,
              encryptionContext,
              suite,
              maxPlaintextLength,
              required,
              null,
              keyDescription,
              null,
              error
            );
          }
        case "negative-decrypt-keyring":
          {
            KeyDescription encrypt = KeyDescription.parse(Json.get("encryptKeyDescription", json));
            KeyDescription decrypt = KeyDescription.parse(Json.get("decryptKeyDescription", json));
            return new EncryptVector(
              EncryptKind.NEGATIVE_DECRYPT,
              name,
              description,
              encryptionContext,
              suite,
              maxPlaintextLength,
              required,
              reproduced,
              encrypt,
              decrypt,
              Json.getString("decryptErrorDescription", json)
            );
          }
        default:
          throw new VectorException("Unsupported EncryptTestVector type:" + type);
      }
    }

    /**
     * EncryptTestToDecryptVector, for POSITIVE and NEGATIVE_DECRYPT. The required keys are removed from the stored
     * context: the decrypting caller must reproduce them.
     */
    DecryptVector toDecryptVector(Side.Encrypted materials) {
      List<String> keysToRemove = requiredEncryptionContextKeys == null ? Collections.emptyList() : requiredEncryptionContextKeys;
      Map<String, String> source = kind == EncryptKind.POSITIVE ? materials.encryptionContext : encryptionContext;
      Map<String, String> stored = new LinkedHashMap<>(source);
      stored.keySet().removeAll(keysToRemove);
      Optional<String> text = description.map(d -> "Decryption for " + d);
      if (kind == EncryptKind.POSITIVE) {
        byte[] symmetricSigningKey = materials.symmetricSigningKeys.isEmpty() ? null : materials.symmetricSigningKeys.get(0);
        return new DecryptVector(
          DecryptKind.POSITIVE,
          name + "->Decryption",
          text,
          algorithmSuite,
          materials.encryptedDataKeys,
          stored,
          reproducedEncryptionContext,
          decryptDescription,
          new DecryptVector.Expected(materials.plaintextDataKey, symmetricSigningKey, keysToRemove),
          null
        );
      }
      return new DecryptVector(
        DecryptKind.NEGATIVE,
        name + "->Decryption",
        text,
        algorithmSuite,
        materials.encryptedDataKeys,
        stored,
        reproducedEncryptionContext,
        decryptDescription,
        null,
        errorDescription
      );
    }
  }

  static final class DecryptVector {

    /** DecryptResult: what DecryptMaterials must return. Keys are null when absent. */
    static final class Expected {

      final byte[] plaintextDataKey;
      final byte[] symmetricSigningKey;
      final List<String> requiredEncryptionContextKeys;

      Expected(byte[] plaintextDataKey, byte[] symmetricSigningKey, List<String> requiredEncryptionContextKeys) {
        this.plaintextDataKey = plaintextDataKey;
        this.symmetricSigningKey = symmetricSigningKey;
        this.requiredEncryptionContextKeys = Collections.unmodifiableList(new ArrayList<>(requiredEncryptionContextKeys));
      }
    }

    final DecryptKind kind;
    final String name;
    final Optional<String> description;
    final AlgorithmSuite algorithmSuite;
    final List<Edk> encryptedDataKeys;
    final Map<String, String> encryptionContext;
    /** Null when absent. */
    final Map<String, String> reproducedEncryptionContext;
    final KeyDescription keyDescription;
    /** Null for NEGATIVE. */
    final Expected expected;
    /** Null for POSITIVE. */
    final String errorDescription;

    DecryptVector(
      DecryptKind kind,
      String name,
      Optional<String> description,
      AlgorithmSuite algorithmSuite,
      List<Edk> encryptedDataKeys,
      Map<String, String> encryptionContext,
      Map<String, String> reproducedEncryptionContext,
      KeyDescription keyDescription,
      Expected expected,
      String errorDescription
    ) {
      this.kind = kind;
      this.name = name;
      this.description = description;
      this.algorithmSuite = algorithmSuite;
      this.encryptedDataKeys = Collections.unmodifiableList(new ArrayList<>(encryptedDataKeys));
      this.encryptionContext = Collections.unmodifiableMap(new LinkedHashMap<>(encryptionContext));
      this.reproducedEncryptionContext = reproducedEncryptionContext == null
        ? null
        : Collections.unmodifiableMap(new LinkedHashMap<>(reproducedEncryptionContext));
      this.keyDescription = keyDescription;
      this.expected = expected;
      this.errorDescription = errorDescription;
    }

    CommitmentPolicy commitmentPolicy() {
      return compatibleCommitmentPolicy(algorithmSuite);
    }

    /** DecryptTestVectorToJson. */
    ObjectNode toJson() {
      String id = hex(algorithmSuite);
      ObjectNode json = Json.NODES.objectNode().put("type", kind.type).put("description", name + " " + id);
      if (kind == DecryptKind.NEGATIVE) {
        json.put("errorDescription", errorDescription);
      }
      json.put("algorithmSuiteId", id);
      json.set("keyDescription", keyDescription.toJson());
      ArrayNode edks = json.putArray("encryptedDataKeys");
      encryptedDataKeys.forEach(edk -> edks.add(edk.toJson()));
      if (kind == DecryptKind.POSITIVE) {
        ObjectNode result = json.putObject("result");
        if (expected.plaintextDataKey != null) {
          result.put("plaintextDataKey", Json.base64(expected.plaintextDataKey));
        }
        if (expected.symmetricSigningKey != null) {
          result.put("symmetricSigningKey", Json.base64(expected.symmetricSigningKey));
        }
        result.set("requiredEncryptionContextKeys", Json.strings(expected.requiredEncryptionContextKeys));
      }
      if (reproducedEncryptionContext != null) {
        json.set("reproducedEncryptionContext", Json.stringMap(reproducedEncryptionContext));
      }
      json.set("encryptionContext", Json.stringMap(encryptionContext));
      return json;
    }

    /** ToDecryptTestVector. */
    static DecryptVector parse(String name, JsonNode json) {
      Json.object(json, "DecryptTestVector");
      String type = Json.getString("type", json);
      Optional<String> description = Json.getOptionalString("description", json);
      Map<String, String> encryptionContext = Json.stringMap("encryptionContext", json);
      AlgorithmSuite suite = algorithmSuite(json);
      Map<String, String> reproduced = Json.optionalStringMap("reproducedEncryptionContext", json).orElse(null);
      KeyDescription keyDescription = KeyDescription.parse(Json.get("keyDescription", json));
      List<Edk> edks = new ArrayList<>();
      for (JsonNode edk : Json.getArray("encryptedDataKeys", json)) {
        if (!edk.isObject()) {
          throw new VectorException("Encrypted data key is not an object");
        }
        edks.add(Edk.parse(edk));
      }
      switch (type) {
        case "positive-keyring":
          {
            JsonNode result = Json.getObject("result", json);
            byte[] plaintextDataKey = Json.getOptionalString("plaintextDataKey", result).map(Json::base64).orElse(null);
            byte[] symmetricSigningKey = Json.getOptionalString("symmetricSigningKey", result).map(Json::base64).orElse(null);
            List<String> required = Json.getArrayString("requiredEncryptionContextKeys", result);
            return new DecryptVector(
              DecryptKind.POSITIVE,
              name,
              description,
              suite,
              edks,
              encryptionContext,
              reproduced,
              keyDescription,
              new Expected(plaintextDataKey, symmetricSigningKey, required),
              null
            );
          }
        case "negative-keyring":
          return new DecryptVector(
            DecryptKind.NEGATIVE,
            name,
            description,
            suite,
            edks,
            encryptionContext,
            reproduced,
            keyDescription,
            null,
            Json.getString("errorDescription", json)
          );
        default:
          throw new VectorException("Unsupported DecryptTestVector type:" + type);
      }
    }
  }

  /** GetAlgorithmSuiteInfo: the suite of a loose hex {@code algorithmSuiteId}. */
  static AlgorithmSuite algorithmSuite(JsonNode json) {
    String hex = Json.getString("algorithmSuiteId", json);
    // IsLooseHexString: hex digits in either case; FromHexString pads an odd length with a leading zero.
    if (!hex.matches("[0-9a-fA-F]*")) {
      throw new VectorException("Not hex encoded binary");
    }
    String even = hex.length() % 2 == 0 ? hex : "0" + hex;
    byte[] binaryId = new byte[even.length() / 2];
    for (int i = 0; i < binaryId.length; i++) {
      binaryId[i] = (byte) Integer.parseInt(even.substring(2 * i, 2 * i + 2), 16);
    }
    try {
      return AllSuites.fromBinaryId(binaryId);
    } catch (RuntimeException e) {
      throw new VectorException("Invalid Suite:" + hex);
    }
  }

  /** AllAlgorithmSuites.ToHex: lower-case hex of the binary id. */
  static String hex(AlgorithmSuite suite) {
    StringBuilder hex = new StringBuilder();
    for (byte b : suite.binaryId()) {
      hex.append(String.format("%02x", b));
    }
    return hex.toString();
  }

  /** GetCompatibleCommitmentPolicy. */
  static CommitmentPolicy compatibleCommitmentPolicy(AlgorithmSuite suite) {
    if (suite.format() == AlgorithmSuite.Format.DBE) {
      return DbeCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT;
    }
    return suite.isCommitting() ? EsdkCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT : EsdkCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT;
  }

  static List<AlgorithmSuite> allSuites() {
    return AllSuites.all();
  }

  private static List<String> requiredEncryptionContextKeys(JsonNode json) {
    // GetArrayString(...).ToOption(): anything but an array of strings means none.
    try {
      return Json.getArrayString("requiredEncryptionContextKeys", json);
    } catch (VectorException e) {
      return null;
    }
  }

  // GetString(...).ToOption(): the encrypt manifest's description may be anything.
  private static Optional<String> optionalString(String key, JsonNode json) {
    JsonNode value = json.get(key);
    return value != null && value.isTextual() ? Optional.of(value.asText()) : Optional.empty();
  }
}
