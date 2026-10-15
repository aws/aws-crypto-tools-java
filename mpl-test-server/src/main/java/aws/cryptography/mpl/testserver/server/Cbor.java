package aws.cryptography.mpl.testserver.server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * CBOR read/write helpers: blobs travel as byte strings, enums as text. A missing or
 * mistyped member is the harness's fault, so it is a GenericServerError.
 */
final class Cbor {

  private static final ObjectMapper MAPPER = new ObjectMapper(new CBORFactory());

  private Cbor() {}

  static JsonNode decode(byte[] body) {
    try {
      JsonNode node = MAPPER.readTree(body);
      if (node == null || !node.isObject()) {
        throw ModeledError.generic("request body is not a CBOR map");
      }
      return node;
    } catch (IOException e) {
      throw ModeledError.generic("failed to decode CBOR request: " + e.getMessage());
    }
  }

  static byte[] encode(ObjectNode node) {
    try {
      return MAPPER.writeValueAsBytes(node);
    } catch (IOException e) {
      throw ModeledError.generic("failed to encode CBOR response: " + e.getMessage());
    }
  }

  static ObjectNode object() {
    return MAPPER.createObjectNode();
  }

  static ArrayNode array() {
    return MAPPER.createArrayNode();
  }

  static boolean present(JsonNode node, String field) {
    JsonNode value = node.get(field);
    return value != null && !value.isNull();
  }

  static JsonNode member(JsonNode node, String field) {
    if (!present(node, field)) {
      throw ModeledError.generic("missing required member: " + field);
    }
    return node.get(field);
  }

  static byte[] blob(JsonNode node, String field) {
    return blobValue(member(node, field), field);
  }

  /** The blob, or null when absent. */
  static byte[] optionalBlob(JsonNode node, String field) {
    return present(node, field) ? blob(node, field) : null;
  }

  static String string(JsonNode node, String field) {
    JsonNode value = member(node, field);
    if (!value.isTextual()) {
      throw ModeledError.generic("member is not a string: " + field);
    }
    return value.asText();
  }

  static long longValue(JsonNode node, String field) {
    JsonNode value = member(node, field);
    if (!value.isIntegralNumber() || !value.canConvertToLong()) {
      throw ModeledError.generic("member is not a long: " + field);
    }
    return value.asLong();
  }

  /** An optional string-to-string map member; absent means empty. */
  static Map<String, String> stringMap(JsonNode node, String field) {
    Map<String, String> out = new LinkedHashMap<>();
    if (!present(node, field)) {
      return out;
    }
    JsonNode value = node.get(field);
    if (!value.isObject()) {
      throw ModeledError.generic("member is not a map: " + field);
    }
    Iterator<Map.Entry<String, JsonNode>> fields = value.fields();
    while (fields.hasNext()) {
      Map.Entry<String, JsonNode> entry = fields.next();
      if (!entry.getValue().isTextual()) {
        throw ModeledError.generic("map value is not a string: " + field + "." + entry.getKey());
      }
      out.put(entry.getKey(), entry.getValue().asText());
    }
    return out;
  }

  static Map<String, String> requiredStringMap(JsonNode node, String field) {
    member(node, field);
    return stringMap(node, field);
  }

  static List<String> requiredStringList(JsonNode node, String field) {
    member(node, field);
    return stringList(node, field);
  }

  /** A list-of-strings member; absent means empty. */
  static List<String> stringList(JsonNode node, String field) {
    List<String> out = new ArrayList<>();
    if (!present(node, field)) {
      return out;
    }
    for (JsonNode element : list(node, field)) {
      if (!element.isTextual()) {
        throw ModeledError.generic("list element is not a string: " + field);
      }
      out.add(element.asText());
    }
    return out;
  }

  /** A list-of-blobs member, or null when absent. */
  static List<byte[]> optionalBlobList(JsonNode node, String field) {
    if (!present(node, field)) {
      return null;
    }
    List<byte[]> out = new ArrayList<>();
    for (JsonNode element : list(node, field)) {
      out.add(blobValue(element, field));
    }
    return out;
  }

  /** A union member: a map with exactly one entry, whose key names the variant. */
  static Map.Entry<String, JsonNode> union(JsonNode node, String field) {
    JsonNode value = member(node, field);
    if (!value.isObject() || value.size() != 1) {
      throw ModeledError.generic("member is not a union (a map with one entry): " + field);
    }
    return value.fields().next();
  }

  static JsonNode list(JsonNode node, String field) {
    JsonNode value = member(node, field);
    if (!value.isArray()) {
      throw ModeledError.generic("member is not a list: " + field);
    }
    return value;
  }

  static void putMap(ObjectNode node, String field, Map<String, String> map) {
    ObjectNode out = node.putObject(field);
    for (Map.Entry<String, String> entry : map.entrySet()) {
      out.put(entry.getKey(), entry.getValue());
    }
  }

  static void putStringList(ObjectNode node, String field, List<String> list) {
    ArrayNode out = node.putArray(field);
    for (String value : list) {
      out.add(value);
    }
  }

  private static byte[] blobValue(JsonNode value, String field) {
    if (!value.isBinary()) {
      throw ModeledError.generic("member is not a blob: " + field);
    }
    try {
      return value.binaryValue();
    } catch (IOException e) {
      throw ModeledError.generic("invalid blob member: " + field);
    }
  }
}
