// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.vectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import software.amazon.cryptography.mpl.keyrings.PaddingScheme;

/**
 * A keyring or CMM a test vector names: the KeyDescription union of key-vectors.smithy,
 * read and written as KeyDescription.dfy does (ToKeyDescription, ToJson version 3).
 */
abstract class KeyDescription {

  /** The manifest {@code type}, refined for raw keyrings, to group vector counts. */
  abstract String kind();

  /** The key id KeyringFromKeyDescription.GetKeyId uses to find the key material. */
  abstract String keyId();

  abstract ObjectNode toJson();

  /** Keyring?: every description but a CMM. */
  boolean isKeyring() {
    return !(this instanceof RequiredEncryptionContext);
  }

  static KeyDescription parse(JsonNode json) {
    if (json.isArray()) {
      if (json.size() < 1) {
        throw new VectorException("Need at least one element in a JSON Array.");
      }
      for (JsonNode element : json) {
        if (!element.isObject()) {
          throw new VectorException("No nested arrays.");
        }
      }
      List<JsonNode> children = new ArrayList<>();
      json.forEach(children::add);
      return multi(Optional.of(children.get(0)), children.subList(1, children.size()));
    }
    Json.object(json, "KeyDescription");
    String type = Json.getString("type", json);
    switch (type) {
      case "aws-kms-mrk-aware-discovery":
        return new KmsMrkDiscovery("aws-kms-mrk-aware-discovery", Json.getString("default-mrk-region", json), discoveryFilter(json));
      case "multi-keyring":
        return multi(Json.find("generator", json), Json.getArray("childKeyrings", json));
      case "required-encryption-context-cmm":
        {
          KeyDescription underlying = parse(Json.get("underlying", json));
          // GetArrayString(...).ToOption().UnwrapOr([]): anything but an array of strings means no keys.
          List<String> keys;
          try {
            keys = Json.getArrayString("requiredEncryptionContextKeys", json);
          } catch (VectorException e) {
            keys = Collections.emptyList();
          }
          return new RequiredEncryptionContext(underlying, keys);
        }
      case "raw-ecdh":
        return new RawEcdh(
          Json.getString("sender", json),
          Json.getString("recipient", json),
          Json.getString("sender-public-key", json),
          Json.getString("recipient-public-key", json),
          Json.getString("provider-id", json),
          Json.getString("ecc-curve", json),
          Json.getString("schema", json)
        );
      case "aws-kms-ecdh":
        {
          String curve = Json.getString("ecc-curve", json);
          if (!KmsEcdh.CURVES.contains(curve)) {
            throw new VectorException("Unsupported ECC Curve Spec:" + curve);
          }
          return new KmsEcdh(
            Json.getString("sender", json),
            Json.getString("recipient", json),
            Json.getString("sender-public-key", json),
            Json.getString("recipient-public-key", json),
            curve,
            Json.getString("schema", json)
          );
        }
      case "static-material-keyring":
      case "aws-kms":
      case "aws-kms-mrk-aware":
      case "aws-kms-rsa":
      case "aws-kms-hierarchy":
      case "raw":
        return keyed(type, Json.getString("key", json), json);
      default:
        throw new VectorException("Unsupported KeyDescription type:" + type);
    }
  }

  private static KeyDescription keyed(String type, String key, JsonNode json) {
    switch (type) {
      case "static-material-keyring":
        return new Static(key);
      case "aws-kms":
        return new Kms(key);
      case "aws-kms-mrk-aware":
        return new KmsMrk(key);
      case "aws-kms-rsa":
        {
          String algorithm = Json.getString("encryption-algorithm", json);
          if (!KmsRsa.ALGORITHMS.contains(algorithm)) {
            throw new VectorException("Unsupported EncryptionAlgorithmSpec:" + algorithm);
          }
          return new KmsRsa(key, algorithm);
        }
      case "aws-kms-hierarchy":
        return new Hierarchy(key);
      default:
        {
          String algorithm = Json.getString("encryption-algorithm", json);
          switch (algorithm) {
            case "aes":
              return new RawAes(key, Json.getString("provider-id", json));
            case "rsa":
              return rawRsa(key, json);
            default:
              throw new VectorException("Unsupported algorithm:" + algorithm);
          }
        }
    }
  }

  private static RawRsa rawRsa(String key, JsonNode json) {
    String providerId = Json.getString("provider-id", json);
    String paddingAlgorithm = Json.getString("padding-algorithm", json);
    Optional<String> paddingHash = Json.getOptionalString("padding-hash", json);
    if (!paddingHash.isPresent() && !paddingAlgorithm.equals("pkcs1")) {
      throw new VectorException("oaep-mgf1 MUST define padding-hash");
    }
    String hash = paddingHash.orElse("sha1");
    for (PaddingScheme padding : PaddingScheme.values()) {
      String[] names = RawRsa.names(padding);
      if (names[0].equals(paddingAlgorithm) && names[1].equals(hash)) {
        return new RawRsa(key, providerId, padding);
      }
    }
    throw new VectorException("Unsupported padding:" + paddingAlgorithm + " hash:" + hash);
  }

  private static Optional<KmsMrkDiscovery.Filter> discoveryFilter(JsonNode json) {
    JsonNode filter = json.get("aws-kms-discovery-filter");
    if (filter == null || !filter.isObject()) {
      return Optional.empty();
    }
    JsonNode partition = filter.get("partition");
    JsonNode accounts = filter.get("account-ids");
    if (partition == null || !partition.isTextual() || accounts == null || !accounts.isArray()) {
      return Optional.empty();
    }
    List<String> accountIds = new ArrayList<>();
    for (JsonNode account : accounts) {
      if (!account.isTextual()) {
        return Optional.empty();
      }
      accountIds.add(account.asText());
    }
    return Optional.of(new KmsMrkDiscovery.Filter(partition.asText(), accountIds));
  }

  private static Multi multi(Optional<JsonNode> generator, List<JsonNode> children) {
    if (generator.isPresent() && !generator.get().isObject()) {
      throw new VectorException("Not an object");
    }
    List<KeyDescription> childKeyrings = new ArrayList<>();
    for (JsonNode child : children) {
      childKeyrings.add(parse(child));
    }
    return new Multi(generator.isPresent() ? parse(generator.get()) : null, childKeyrings);
  }

  private static ObjectNode typed(String type) {
    return Json.NODES.objectNode().put("type", type);
  }

  static final class Kms extends KeyDescription {

    final String keyId;

    Kms(String keyId) {
      this.keyId = keyId;
    }

    @Override
    String kind() {
      return "aws-kms";
    }

    @Override
    String keyId() {
      return keyId;
    }

    @Override
    ObjectNode toJson() {
      return typed("aws-kms").put("key", keyId);
    }
  }

  static final class KmsMrk extends KeyDescription {

    final String keyId;

    KmsMrk(String keyId) {
      this.keyId = keyId;
    }

    @Override
    String kind() {
      return "aws-kms-mrk-aware";
    }

    @Override
    String keyId() {
      return keyId;
    }

    @Override
    ObjectNode toJson() {
      return typed("aws-kms-mrk-aware").put("key", keyId);
    }
  }

  static final class KmsMrkDiscovery extends KeyDescription {

    static final class Filter {

      final String partition;
      final List<String> accountIds;

      Filter(String partition, List<String> accountIds) {
        this.partition = partition;
        this.accountIds = Collections.unmodifiableList(new ArrayList<>(accountIds));
      }
    }

    final String keyId;
    final String defaultMrkRegion;
    final Optional<Filter> filter;

    KmsMrkDiscovery(String keyId, String defaultMrkRegion, Optional<Filter> filter) {
      this.keyId = keyId;
      this.defaultMrkRegion = defaultMrkRegion;
      this.filter = filter;
    }

    @Override
    String kind() {
      return "aws-kms-mrk-aware-discovery";
    }

    @Override
    String keyId() {
      return keyId;
    }

    @Override
    ObjectNode toJson() {
      ObjectNode json = typed("aws-kms-mrk-aware-discovery").put("default-mrk-region", defaultMrkRegion);
      if (filter.isPresent()) {
        ObjectNode filterJson = json.putObject("aws-kms-discovery-filter");
        filterJson.put("partition", filter.get().partition);
        filterJson.set("account-ids", Json.strings(filter.get().accountIds));
      }
      return json;
    }
  }

  static final class RawRsa extends KeyDescription {

    final String keyId;
    final String providerId;
    final PaddingScheme padding;

    RawRsa(String keyId, String providerId, PaddingScheme padding) {
      this.keyId = keyId;
      this.providerId = providerId;
      this.padding = padding;
    }

    // PaddingAlgorithmString2String.
    static String[] names(PaddingScheme padding) {
      switch (padding) {
        case PKCS1:
          return new String[] { "pkcs1", "sha1" };
        case OAEP_SHA1_MGF1:
          return new String[] { "oaep-mgf1", "sha1" };
        case OAEP_SHA256_MGF1:
          return new String[] { "oaep-mgf1", "sha256" };
        case OAEP_SHA384_MGF1:
          return new String[] { "oaep-mgf1", "sha384" };
        case OAEP_SHA512_MGF1:
          return new String[] { "oaep-mgf1", "sha512" };
        default:
          throw new IllegalArgumentException(padding.name());
      }
    }

    @Override
    String kind() {
      return "raw-rsa";
    }

    @Override
    String keyId() {
      return keyId;
    }

    @Override
    ObjectNode toJson() {
      String[] names = names(padding);
      return typed("raw")
        .put("key", keyId)
        .put("provider-id", providerId)
        .put("encryption-algorithm", "rsa")
        .put("padding-algorithm", names[0])
        .put("padding-hash", names[1]);
    }
  }

  static final class RawAes extends KeyDescription {

    final String keyId;
    final String providerId;

    RawAes(String keyId, String providerId) {
      this.keyId = keyId;
      this.providerId = providerId;
    }

    @Override
    String kind() {
      return "raw-aes";
    }

    @Override
    String keyId() {
      return keyId;
    }

    @Override
    ObjectNode toJson() {
      return typed("raw").put("key", keyId).put("provider-id", providerId).put("encryption-algorithm", "aes");
    }
  }

  static final class RawEcdh extends KeyDescription {

    final String senderKeyId;
    final String recipientKeyId;
    final String senderPublicKey;
    final String recipientPublicKey;
    final String providerId;
    final String curveSpec;
    final String keyAgreementScheme;

    RawEcdh(
      String senderKeyId,
      String recipientKeyId,
      String senderPublicKey,
      String recipientPublicKey,
      String providerId,
      String curveSpec,
      String keyAgreementScheme
    ) {
      this.senderKeyId = senderKeyId;
      this.recipientKeyId = recipientKeyId;
      this.senderPublicKey = senderPublicKey;
      this.recipientPublicKey = recipientPublicKey;
      this.providerId = providerId;
      this.curveSpec = curveSpec;
      this.keyAgreementScheme = keyAgreementScheme;
    }

    @Override
    String kind() {
      return "raw-ecdh";
    }

    @Override
    String keyId() {
      return senderKeyId;
    }

    @Override
    ObjectNode toJson() {
      return typed("raw-ecdh")
        .put("sender", senderKeyId)
        .put("recipient", recipientKeyId)
        .put("sender-public-key", senderPublicKey)
        .put("recipient-public-key", recipientPublicKey)
        .put("provider-id", providerId)
        .put("ecc-curve", curveSpec)
        .put("schema", keyAgreementScheme);
    }
  }

  static final class Static extends KeyDescription {

    final String keyId;

    Static(String keyId) {
      this.keyId = keyId;
    }

    @Override
    String kind() {
      return "static-material-keyring";
    }

    @Override
    String keyId() {
      return keyId;
    }

    @Override
    ObjectNode toJson() {
      return typed("static-material-keyring").put("key", keyId);
    }
  }

  static final class KmsRsa extends KeyDescription {

    // EncryptionAlgorithmSpec2String: SYMMETRIC_DEFAULT is not an RSA algorithm.
    static final List<String> ALGORITHMS = Arrays.asList("RSAES_OAEP_SHA_1", "RSAES_OAEP_SHA_256");

    final String keyId;
    final String encryptionAlgorithm;

    KmsRsa(String keyId, String encryptionAlgorithm) {
      this.keyId = keyId;
      this.encryptionAlgorithm = encryptionAlgorithm;
    }

    @Override
    String kind() {
      return "aws-kms-rsa";
    }

    @Override
    String keyId() {
      return keyId;
    }

    @Override
    ObjectNode toJson() {
      return typed("aws-kms-rsa").put("key", keyId).put("encryption-algorithm", encryptionAlgorithm);
    }
  }

  static final class KmsEcdh extends KeyDescription {

    // KmsKey2EccAlgorithmSpec: the curve is named by the key.
    static final List<String> CURVES = Arrays.asList("us-west-2-256-ecc", "us-west-2-384-ecc", "us-west-2-521-ecc");

    final String senderKeyId;
    final String recipientKeyId;
    final String senderPublicKey;
    final String recipientPublicKey;
    final String curveSpec;
    final String keyAgreementScheme;

    KmsEcdh(
      String senderKeyId,
      String recipientKeyId,
      String senderPublicKey,
      String recipientPublicKey,
      String curveSpec,
      String keyAgreementScheme
    ) {
      this.senderKeyId = senderKeyId;
      this.recipientKeyId = recipientKeyId;
      this.senderPublicKey = senderPublicKey;
      this.recipientPublicKey = recipientPublicKey;
      this.curveSpec = curveSpec;
      this.keyAgreementScheme = keyAgreementScheme;
    }

    @Override
    String kind() {
      return "aws-kms-ecdh";
    }

    @Override
    String keyId() {
      return senderKeyId;
    }

    @Override
    ObjectNode toJson() {
      return typed("aws-kms-ecdh")
        .put("sender", senderKeyId)
        .put("recipient", recipientKeyId)
        .put("sender-public-key", senderPublicKey)
        .put("recipient-public-key", recipientPublicKey)
        .put("ecc-curve", curveSpec)
        .put("schema", keyAgreementScheme);
    }
  }

  static final class Hierarchy extends KeyDescription {

    final String keyId;

    Hierarchy(String keyId) {
      this.keyId = keyId;
    }

    @Override
    String kind() {
      return "aws-kms-hierarchy";
    }

    @Override
    String keyId() {
      return keyId;
    }

    @Override
    ObjectNode toJson() {
      return typed("aws-kms-hierarchy").put("key", keyId);
    }
  }

  static final class Multi extends KeyDescription {

    final KeyDescription generator;
    final List<KeyDescription> childKeyrings;

    Multi(KeyDescription generator, List<KeyDescription> childKeyrings) {
      this.generator = generator;
      this.childKeyrings = Collections.unmodifiableList(new ArrayList<>(childKeyrings));
    }

    @Override
    String kind() {
      return "multi-keyring";
    }

    // The multi keyring does not have a key id.
    @Override
    String keyId() {
      return "";
    }

    @Override
    ObjectNode toJson() {
      if ((generator != null && !generator.isKeyring()) || childKeyrings.stream().anyMatch(c -> !c.isKeyring())) {
        throw new VectorException("CMMs not supported by Multi Keyrings");
      }
      ObjectNode json = typed("multi-keyring");
      ArrayNode children = json.putArray("childKeyrings");
      childKeyrings.forEach(c -> children.add(c.toJson()));
      if (generator != null) {
        json.set("generator", generator.toJson());
      }
      return json;
    }
  }

  static final class RequiredEncryptionContext extends KeyDescription {

    final KeyDescription underlying;
    final List<String> requiredEncryptionContextKeys;

    RequiredEncryptionContext(KeyDescription underlying, List<String> requiredEncryptionContextKeys) {
      this.underlying = underlying;
      this.requiredEncryptionContextKeys = Collections.unmodifiableList(new ArrayList<>(requiredEncryptionContextKeys));
    }

    @Override
    String kind() {
      return "required-encryption-context-cmm";
    }

    @Override
    String keyId() {
      return underlying.keyId();
    }

    @Override
    ObjectNode toJson() {
      ObjectNode json = typed("required-encryption-context-cmm");
      json.set("underlying", underlying.toJson());
      json.set("requiredEncryptionContextKeys", Json.strings(requiredEncryptionContextKeys));
      return json;
    }
  }
}
