// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.vectors;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import software.amazon.cryptography.mpl.AlgorithmSuite;

/** The keys of a keys manifest (keys.json), read as KeyMaterial.dfy does. */
abstract class KeyMaterial {

  // KeyMaterialString?.
  private static final List<String> TYPES = Arrays.asList(
    "static-material",
    "aws-kms",
    "symmetric",
    "private",
    "public",
    "static-branch-key",
    "aws-kms-rsa",
    "ecc-private",
    "aws-kms-ecdh"
  );

  final String name;

  KeyMaterial(String name) {
    this.name = name;
  }

  /** BuildKeyMaterials over the {@code keys} object of a keys manifest. */
  static Map<String, KeyMaterial> parseKeys(JsonNode keysManifest) {
    JsonNode keys = keysManifest.get("keys");
    if (keys == null || !keys.isObject()) {
      throw new VectorException("keys manifest has no keys object");
    }
    Map<String, KeyMaterial> materials = new LinkedHashMap<>();
    Iterator<Map.Entry<String, JsonNode>> fields = keys.fields();
    while (fields.hasNext()) {
      Map.Entry<String, JsonNode> field = fields.next();
      materials.put(field.getKey(), parse(field.getKey(), field.getValue()));
    }
    return materials;
  }

  private static KeyMaterial parse(String name, JsonNode json) {
    Json.object(json, "KeyDescription");
    String type = Json.getString("type", json);
    if (!TYPES.contains(type)) {
      throw new VectorException("Unsupported KeyMaterial type:" + type);
    }
    if (type.equals("static-material")) {
      return StaticMaterial.parse(name, json);
    }
    if (type.equals("static-branch-key")) {
      return new StaticBranchKey(
        name,
        Json.getString("key-id", json),
        Json.getString("branchKeyVersion", json),
        Json.base64(Json.getString("branchKey", json))
      );
    }
    boolean encrypt = Json.getBool("encrypt", json);
    boolean decrypt = Json.getBool("decrypt", json);
    String keyIdentifier = Json.getOptionalString("key-id", json).orElse(name);
    switch (type) {
      case "aws-kms":
        return new Kms(name, keyIdentifier);
      case "aws-kms-ecdh":
        Json.getString("algorithm", json);
        Json.getString("encoding", json);
        return new KmsEcdh(
          name,
          keyIdentifier,
          Json.getString("sender-material", json),
          Json.getString("recipient-material", json),
          Json.getString("sender-material-public-key", json),
          Json.getString("recipient-material-public-key", json)
        );
      case "ecc-private":
        Json.getString("algorithm", json);
        Json.getNat("bits", json);
        Json.getString("encoding", json);
        return new PrivateEcdh(
          name,
          keyIdentifier,
          Json.getString("sender-material", json),
          Json.getString("recipient-material", json),
          Json.getString("sender-material-public-key", json),
          Json.getString("recipient-material-public-key", json)
        );
      default:
        break;
    }
    Json.getString("algorithm", json);
    long bits = Json.getNat("bits", json);
    Json.getString("encoding", json);
    String material = material(Json.get("material", json));
    switch (type) {
      case "symmetric":
        return new Symmetric(name, keyIdentifier, bits, Json.base64(material));
      case "private":
        return new PrivateRsa(name, keyIdentifier, decrypt, material);
      case "public":
        return new PublicRsa(name, keyIdentifier, encrypt, material);
      default:
        return new KmsRsa(name, keyIdentifier, material);
    }
  }

  // Version 1.0 of the keys manifest stores material as an array of lines.
  private static String material(JsonNode material) {
    if (material.isTextual()) {
      return material.asText();
    }
    if (material.isArray() && material.size() > 0) {
      List<String> lines = new ArrayList<>();
      for (JsonNode line : material) {
        if (!line.isTextual()) {
          throw new VectorException("Unsupported material shape.");
        }
        lines.add(line.asText());
      }
      return String.join("\n", lines);
    }
    throw new VectorException("Unsupported material shape.");
  }

  static final class Symmetric extends KeyMaterial {

    final String keyIdentifier;
    final long bits;
    final byte[] wrappingKey;

    Symmetric(String name, String keyIdentifier, long bits, byte[] wrappingKey) {
      super(name);
      this.keyIdentifier = keyIdentifier;
      this.bits = bits;
      this.wrappingKey = wrappingKey;
    }
  }

  static final class PrivateRsa extends KeyMaterial {

    final String keyIdentifier;
    final boolean decrypt;
    final String pem;

    PrivateRsa(String name, String keyIdentifier, boolean decrypt, String pem) {
      super(name);
      this.keyIdentifier = keyIdentifier;
      this.decrypt = decrypt;
      this.pem = pem;
    }
  }

  static final class PublicRsa extends KeyMaterial {

    final String keyIdentifier;
    final boolean encrypt;
    final String pem;

    PublicRsa(String name, String keyIdentifier, boolean encrypt, String pem) {
      super(name);
      this.keyIdentifier = keyIdentifier;
      this.encrypt = encrypt;
      this.pem = pem;
    }
  }

  static final class PrivateEcdh extends KeyMaterial {

    final String keyIdentifier;
    final String senderPem;
    final String recipientPem;
    final String senderPublicKey;
    final String recipientPublicKey;

    PrivateEcdh(String name, String keyIdentifier, String senderPem, String recipientPem, String senderPublicKey, String recipientPublicKey) {
      super(name);
      this.keyIdentifier = keyIdentifier;
      this.senderPem = senderPem;
      this.recipientPem = recipientPem;
      this.senderPublicKey = senderPublicKey;
      this.recipientPublicKey = recipientPublicKey;
    }
  }

  static final class Kms extends KeyMaterial {

    final String keyIdentifier;

    Kms(String name, String keyIdentifier) {
      super(name);
      this.keyIdentifier = keyIdentifier;
    }
  }

  static final class KmsRsa extends KeyMaterial {

    final String keyIdentifier;
    final String publicKeyPem;

    KmsRsa(String name, String keyIdentifier, String publicKeyPem) {
      super(name);
      this.keyIdentifier = keyIdentifier;
      this.publicKeyPem = publicKeyPem;
    }
  }

  static final class KmsEcdh extends KeyMaterial {

    final String keyIdentifier;
    final String senderKeyArn;
    final String recipientKeyArn;
    final String senderPublicKey;
    final String recipientPublicKey;

    KmsEcdh(String name, String keyIdentifier, String senderKeyArn, String recipientKeyArn, String senderPublicKey, String recipientPublicKey) {
      super(name);
      this.keyIdentifier = keyIdentifier;
      this.senderKeyArn = senderKeyArn;
      this.recipientKeyArn = recipientKeyArn;
      this.senderPublicKey = senderPublicKey;
      this.recipientPublicKey = recipientPublicKey;
    }
  }

  /** The branch key a static key store returns for every request (CreateStaticKeyStores.dfy). */
  static final class StaticBranchKey extends KeyMaterial {

    final String keyIdentifier;
    final String branchKeyVersion;
    final byte[] branchKey;

    StaticBranchKey(String name, String keyIdentifier, String branchKeyVersion, byte[] branchKey) {
      super(name);
      this.keyIdentifier = keyIdentifier;
      this.branchKeyVersion = branchKeyVersion;
      this.branchKey = branchKey;
    }
  }

  /** The materials a static-material keyring returns for every request (CreateStaticKeyrings.dfy). */
  static final class StaticMaterial extends KeyMaterial {

    final AlgorithmSuite algorithmSuite;
    final Map<String, String> encryptionContext;
    final List<String> requiredEncryptionContextKeys;
    final List<TestVectors.Edk> encryptedDataKeys;
    /** Null when absent. */
    final byte[] plaintextDataKey;

    private StaticMaterial(
      String name,
      AlgorithmSuite algorithmSuite,
      Map<String, String> encryptionContext,
      List<String> requiredEncryptionContextKeys,
      List<TestVectors.Edk> encryptedDataKeys,
      byte[] plaintextDataKey
    ) {
      super(name);
      this.algorithmSuite = algorithmSuite;
      this.encryptionContext = Collections.unmodifiableMap(encryptionContext);
      this.requiredEncryptionContextKeys = Collections.unmodifiableList(requiredEncryptionContextKeys);
      this.encryptedDataKeys = Collections.unmodifiableList(encryptedDataKeys);
      this.plaintextDataKey = plaintextDataKey;
    }

    // ToStaticMaterial; signing keys are never read ("This is just for now...").
    static StaticMaterial parse(String name, JsonNode json) {
      AlgorithmSuite suite = TestVectors.algorithmSuite(json);
      Map<String, String> encryptionContext = Json.stringMap("encryptionContext", json);
      List<String> required = Json.getArrayString("requiredEncryptionContextKeys", json);
      List<TestVectors.Edk> edks = new ArrayList<>();
      for (JsonNode edk : Json.getArray("encryptedDataKeys", json)) {
        if (!edk.isObject()) {
          throw new VectorException("Not an array of objects");
        }
        edks.add(TestVectors.Edk.parse(edk));
      }
      byte[] plaintextDataKey = Json.getOptionalString("plaintextDataKey", json).map(Json::base64).orElse(null);
      return new StaticMaterial(name, suite, encryptionContext, required, edks, plaintextDataKey);
    }
  }
}
