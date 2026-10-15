// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.fakeaws;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * An AWS JSON protocol error response: HTTP 400 with {@code __type} and a message.
 * The fakes throw it to reject a request; tests pass one to {@code fail(...)} to inject a failure.
 * The AWS SDK maps {@code type} to its modeled exception class, or to the service's base exception.
 */
public final class ServiceError extends RuntimeException {

  private static final long serialVersionUID = 1L;

  private final String type;
  private final ObjectNode body;

  private ServiceError(String type, String message, ObjectNode extra) {
    super(message);
    this.type = type;
    this.body = JsonNodeFactory.instance.objectNode();
    body.put("__type", type);
    if (message != null) {
      body.put("message", message);
    }
    if (extra != null) {
      body.setAll(extra);
    }
  }

  /** An error of a given {@code __type}, such as {@code "KMSInvalidStateException"}. */
  public static ServiceError of(String type, String message) {
    return new ServiceError(type, message, null);
  }

  static ServiceError withFields(String type, String message, ObjectNode extra) {
    return new ServiceError(type, message, extra);
  }

  /** {@code AccessDeniedException}, which KMS and DynamoDB return for a missing IAM permission. */
  public static ServiceError accessDenied(String message) {
    return of("AccessDeniedException", message);
  }

  /** {@code ThrottlingException}; the fake's clients have retries disabled, so the caller sees it. */
  public static ServiceError throttling(String message) {
    return of("ThrottlingException", message);
  }

  public String type() {
    return type;
  }

  ObjectNode body() {
    return body.deepCopy();
  }
}
