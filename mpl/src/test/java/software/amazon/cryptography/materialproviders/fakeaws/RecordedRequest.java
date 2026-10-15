// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.fakeaws;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * One request the fake endpoint received.
 * Headers (User-Agent, signature, invocation id) are not kept: they differ between SDK copies and calls.
 * Neither is the ClientRequestToken of a DynamoDB TransactWriteItems, for the same reason.
 */
public final class RecordedRequest {

  private final String client;
  private final String service;
  private final String operation;
  private final String region;
  private final JsonNode body;

  RecordedRequest(String client, String service, String operation, String region, JsonNode body) {
    this.client = client;
    this.service = service;
    this.operation = operation;
    this.region = region;
    this.body = sorted(body);
    // The SDK generates a random idempotency token for each call whose caller sets none (the MPL never does).
    if (service.equals("dynamodb") && operation.equals("TransactWriteItems")) {
      ((ObjectNode) this.body).remove("ClientRequestToken");
    }
  }

  /** The label of the client's endpoint, see {@link FakeAws#endpoint}. */
  public String client() {
    return client;
  }

  /** {@code "kms"} or {@code "dynamodb"}. */
  public String service() {
    return service;
  }

  /** The operation name, such as {@code "GenerateDataKey"}. */
  public String operation() {
    return operation;
  }

  /** The region in the request's SigV4 credential scope. */
  public String region() {
    return region;
  }

  /** The JSON request body with object fields sorted by name. */
  public JsonNode body() {
    return body.deepCopy();
  }

  /**
   * {@code "<service> <operation> <region> <body>"}, without the client label,
   * so the same call from two clients describes the same.
   * Object fields named in {@code ignoredFields} show as {@code "<ignored>"} at every depth,
   * for values that legitimately differ between the two sides, such as a random plaintext data key.
   */
  public String describe(String... ignoredFields) {
    JsonNode shown = body;
    if (ignoredFields.length > 0) {
      shown = body.deepCopy();
      mask(shown, new HashSet<>(Arrays.asList(ignoredFields)));
    }
    return service + " " + operation + " " + region + " " + shown;
  }

  /** {@link #describe} of each request. */
  public static List<String> describe(List<RecordedRequest> requests, String... ignoredFields) {
    List<String> described = new ArrayList<>();
    for (RecordedRequest request : requests) {
      described.add(request.describe(ignoredFields));
    }
    return described;
  }

  @Override
  public String toString() {
    return client + ": " + describe();
  }

  // Values are replaced, not removed, so a field one side omits still shows.
  private static void mask(JsonNode node, Set<String> fields) {
    if (node instanceof ObjectNode) {
      for (String field : fields) {
        if (node.has(field)) {
          ((ObjectNode) node).put(field, "<ignored>");
        }
      }
    }
    for (JsonNode child : node) {
      mask(child, fields);
    }
  }

  // The two SDK copies may serialize map entries, such as encryption context, in different orders.
  private static JsonNode sorted(JsonNode node) {
    if (node.isObject()) {
      List<String> names = new ArrayList<>();
      Iterator<String> it = node.fieldNames();
      while (it.hasNext()) {
        names.add(it.next());
      }
      Collections.sort(names);
      ObjectNode result = JsonNodeFactory.instance.objectNode();
      for (String name : names) {
        result.set(name, sorted(node.get(name)));
      }
      return result;
    }
    if (node.isArray()) {
      ArrayNode result = JsonNodeFactory.instance.arrayNode();
      for (JsonNode element : node) {
        result.add(sorted(element));
      }
      return result;
    }
    return node;
  }
}
