// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.vectors;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * The manifest JSON accessors of JSONHelpers.dfy, failing with its messages as {@link VectorException}.
 * Duplicate object keys fail the parse, as JsonObjectToStringStringMap rejects them.
 */
final class Json {

  static final JsonNodeFactory NODES = JsonNodeFactory.instance;
  private static final ObjectMapper MAPPER = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

  private Json() {}

  static JsonNode read(InputStream in) {
    try {
      return MAPPER.readTree(in);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  static JsonNode resource(String name) {
    try (InputStream in = Json.class.getResourceAsStream(name)) {
      if (in == null) {
        throw new IllegalStateException("missing test resource " + name);
      }
      return read(in);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /** Serializes and parses again, as the Dafny runner writes each manifest to disk and reads it back. */
  static JsonNode roundTrip(JsonNode node) {
    try {
      return MAPPER.readTree(MAPPER.writeValueAsBytes(node));
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  static ObjectNode object(JsonNode json, String what) {
    if (json == null || !json.isObject()) {
      throw new VectorException(what + " not an object");
    }
    return (ObjectNode) json;
  }

  static JsonNode get(String key, JsonNode obj) {
    JsonNode value = obj.get(key);
    if (value == null) {
      throw new VectorException("Key: " + key + " does not exist");
    }
    return value;
  }

  static Optional<JsonNode> find(String key, JsonNode obj) {
    return Optional.ofNullable(obj.get(key));
  }

  static String getString(String key, JsonNode obj) {
    JsonNode value = get(key, obj);
    if (!value.isTextual()) {
      throw new VectorException("Not a string");
    }
    return value.asText();
  }

  static Optional<String> getOptionalString(String key, JsonNode obj) {
    JsonNode value = obj.get(key);
    if (value == null) {
      return Optional.empty();
    }
    if (!value.isTextual()) {
      throw new VectorException("Not a string");
    }
    return Optional.of(value.asText());
  }

  static boolean getBool(String key, JsonNode obj) {
    JsonNode value = get(key, obj);
    if (!value.isBoolean()) {
      throw new VectorException("Not a bool");
    }
    return value.asBoolean();
  }

  /** GetNat: a number greater than zero. */
  static long getNat(String key, JsonNode obj) {
    JsonNode value = get(key, obj);
    if (!value.isNumber()) {
      throw new VectorException("Not a number");
    }
    if (value.bigIntegerValue().signum() <= 0) {
      throw new VectorException("Not a nat");
    }
    if (!value.canConvertToLong()) {
      throw new VectorException("Int64 Overflow");
    }
    return value.asLong();
  }

  static ObjectNode getObject(String key, JsonNode obj) {
    JsonNode value = get(key, obj);
    if (!value.isObject()) {
      throw new VectorException("Not an object");
    }
    return (ObjectNode) value;
  }

  static List<JsonNode> getArray(String key, JsonNode obj) {
    JsonNode value = get(key, obj);
    if (!value.isArray()) {
      throw new VectorException("Not an array");
    }
    List<JsonNode> elements = new ArrayList<>();
    value.forEach(elements::add);
    return elements;
  }

  static List<String> getArrayString(String key, JsonNode obj) {
    JsonNode value = get(key, obj);
    if (!value.isArray()) {
      throw new VectorException("Not an array of strings");
    }
    List<String> strings = new ArrayList<>();
    for (JsonNode element : value) {
      if (!element.isTextual()) {
        throw new VectorException("Not an array of strings");
      }
      strings.add(element.asText());
    }
    return strings;
  }

  /** SmallObjectToStringStringMap. */
  static Map<String, String> stringMap(String key, JsonNode obj) {
    return stringMap(get(key, obj));
  }

  static Optional<Map<String, String>> optionalStringMap(String key, JsonNode obj) {
    JsonNode value = obj.get(key);
    return value == null ? Optional.empty() : Optional.of(stringMap(value));
  }

  private static Map<String, String> stringMap(JsonNode item) {
    if (!item.isObject()) {
      throw new VectorException("Not an object");
    }
    Map<String, String> map = new LinkedHashMap<>();
    Iterator<Map.Entry<String, JsonNode>> fields = item.fields();
    while (fields.hasNext()) {
      Map.Entry<String, JsonNode> field = fields.next();
      if (!field.getValue().isTextual()) {
        throw new VectorException("Not a string string object");
      }
      map.put(field.getKey(), field.getValue().asText());
    }
    return map;
  }

  static byte[] base64(String encoded) {
    try {
      return Base64.getDecoder().decode(encoded);
    } catch (IllegalArgumentException e) {
      throw new VectorException("Invalid Base64: " + encoded);
    }
  }

  static String base64(byte[] bytes) {
    return Base64.getEncoder().encodeToString(bytes);
  }

  /** An encryption context object with keys in UTF-8 byte order, as EncryptionContextToJson writes it. */
  static ObjectNode stringMap(Map<String, String> map) {
    ObjectNode node = NODES.objectNode();
    for (Map.Entry<String, String> entry : sortedByUtf8(map).entrySet()) {
      node.put(entry.getKey(), entry.getValue());
    }
    return node;
  }

  static ArrayNode strings(Collection<String> strings) {
    ArrayNode node = NODES.arrayNode();
    strings.forEach(node::add);
    return node;
  }

  static <V> Map<String, V> sortedByUtf8(Map<String, V> map) {
    Map<String, V> sorted = new TreeMap<>(Json::compareUtf8);
    sorted.putAll(map);
    return sorted;
  }

  static int compareUtf8(String a, String b) {
    byte[] x = a.getBytes(StandardCharsets.UTF_8);
    byte[] y = b.getBytes(StandardCharsets.UTF_8);
    for (int i = 0; i < Math.min(x.length, y.length); i++) {
      int c = Integer.compare(x[i] & 0xff, y[i] & 0xff);
      if (c != 0) {
        return c;
      }
    }
    return Integer.compare(x.length, y.length);
  }
}
