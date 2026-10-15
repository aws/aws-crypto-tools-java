// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.fakeaws;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;

/**
 * An in-process KMS and DynamoDB endpoint for differential tests.
 *
 * <p>The native MPL and the reference MPL each have their own copy of the AWS SDK,
 * so they cannot share a client; they share this endpoint instead.
 * A data key one side encrypts through its client decrypts through the other side's client,
 * and both sides' requests are recorded for comparison.
 *
 * <p>Each client sends to {@link #endpoint}{@code (label)}; the label tags its recorded requests.
 * {@link #kmsClient(String, String)} and {@link #dynamoDbClient(String, String)} build clients
 * from this module's SDK; the {@code ClassLoader} overloads build them from another SDK copy,
 * such as the reference MPL's. The region a request is signed for is the region it is served in.
 *
 * <pre>{@code
 * try (FakeAws aws = FakeAws.start()) {
 *   String key = aws.kms().createSymmetricKey("us-west-2");
 *   KmsClient kms = aws.kmsClient("native", "us-west-2");
 *   ...
 *   assertEquals(RecordedRequest.describe(aws.requests("native")), RecordedRequest.describe(aws.requests("reference")));
 * }
 * }</pre>
 *
 * <p>Requests are served one at a time, in arrival order.
 */
public final class FakeAws implements AutoCloseable {

  static final ObjectMapper JSON = new ObjectMapper();

  private static final Pattern LABEL = Pattern.compile("[A-Za-z0-9-]+");
  private static final Pattern CREDENTIAL_SCOPE = Pattern.compile("Credential=[^/,]+/[0-9]+/([^/,]+)/([^/,]+)/aws4_request");
  private static final String KMS_TARGET_PREFIX = "TrentService.";
  private static final String DYNAMODB_TARGET_PREFIX = "DynamoDB_20120810.";

  private final HttpServer server;
  private final FakeKms kms = new FakeKms();
  private final FakeDynamoDb dynamoDb = new FakeDynamoDb();
  private final List<RecordedRequest> requests = new ArrayList<>();
  private final List<String> userAgents = new ArrayList<>();
  private final List<Object> clients = new ArrayList<>();
  private long requestIds;

  private FakeAws(HttpServer server) {
    this.server = server;
  }

  /** Starts an endpoint on an ephemeral loopback port. */
  public static FakeAws start() {
    HttpServer server;
    try {
      server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    FakeAws fake = new FakeAws(server);
    server.createContext("/", fake::serve);
    server.start();
    return fake;
  }

  public FakeKms kms() {
    return kms;
  }

  public FakeDynamoDb dynamoDb() {
    return dynamoDb;
  }

  /** The endpoint URI for a client whose requests are recorded under {@code label} (letters, digits, '-'). */
  public URI endpoint(String label) {
    if (!LABEL.matcher(label).matches()) {
      throw new IllegalArgumentException("client label must match " + LABEL + ": " + label);
    }
    return URI.create("http://" + server.getAddress().getHostString() + ":" + server.getAddress().getPort() + "/" + label);
  }

  /** Every recorded request, in arrival order. */
  /** The User-Agent header of each request, as "kms: ..." or "dynamodb: ...", in arrival order. */
  public synchronized List<String> userAgents() {
    return new ArrayList<>(userAgents);
  }

  public synchronized List<RecordedRequest> requests() {
    return new ArrayList<>(requests);
  }

  /** The recorded requests of the clients labeled {@code label}, in arrival order. */
  public synchronized List<RecordedRequest> requests(String label) {
    List<RecordedRequest> selected = new ArrayList<>();
    for (RecordedRequest request : requests) {
      if (request.client().equals(label)) {
        selected.add(request);
      }
    }
    return selected;
  }

  public synchronized void clearRequests() {
    requests.clear();
  }

  /** A KMS client from this module's AWS SDK; {@link #close} closes it. */
  public KmsClient kmsClient(String label, String region) {
    return (KmsClient) kmsClient(FakeAws.class.getClassLoader(), label, region);
  }

  /** A DynamoDB client from this module's AWS SDK; {@link #close} closes it. */
  public DynamoDbClient dynamoDbClient(String label, String region) {
    return (DynamoDbClient) dynamoDbClient(FakeAws.class.getClassLoader(), label, region);
  }

  /** A {@code KmsClient} of the AWS SDK that {@code loader} loads; {@link #close} closes it. */
  public Object kmsClient(ClassLoader loader, String label, String region) {
    return client(loader, "software.amazon.awssdk.services.kms.KmsClient", label, region);
  }

  /** A {@code DynamoDbClient} of the AWS SDK that {@code loader} loads; {@link #close} closes it. */
  public Object dynamoDbClient(ClassLoader loader, String label, String region) {
    return client(loader, "software.amazon.awssdk.services.dynamodb.DynamoDbClient", label, region);
  }

  /** Stops the endpoint and closes the clients it built. */
  @Override
  public void close() {
    List<Object> toClose;
    synchronized (this) {
      toClose = new ArrayList<>(clients);
      clients.clear();
    }
    for (Object client : toClose) {
      reflect(client, "close", new Class<?>[0]);
    }
    server.stop(0);
  }

  // Built by reflection so one code path configures both SDK copies the same way.
  private Object client(ClassLoader loader, String clientInterface, String label, String region) {
    URI endpoint = endpoint(label);
    Object credentials = reflect(
      null,
      load(loader, "software.amazon.awssdk.auth.credentials.AwsBasicCredentials"),
      "create",
      new Class<?>[] { String.class, String.class },
      "AKIAFAKEAWS000000000",
      "fake-secret-access-key"
    );
    Object credentialsProvider = reflect(
      null,
      load(loader, "software.amazon.awssdk.auth.credentials.StaticCredentialsProvider"),
      "create",
      new Class<?>[] { load(loader, "software.amazon.awssdk.auth.credentials.AwsCredentials") },
      credentials
    );
    Object noRetries = reflect(
      null,
      load(loader, "software.amazon.awssdk.awscore.retry.AwsRetryStrategy"),
      "doNotRetry",
      new Class<?>[0]
    );
    Class<?> overrideType = load(loader, "software.amazon.awssdk.core.client.config.ClientOverrideConfiguration");
    Object overrideBuilder = reflect(null, overrideType, "builder", new Class<?>[0]);
    reflect(
      overrideBuilder,
      load(loader, "software.amazon.awssdk.core.client.config.ClientOverrideConfiguration$Builder"),
      "retryStrategy",
      new Class<?>[] { load(loader, "software.amazon.awssdk.retries.api.RetryStrategy") },
      noRetries
    );
    Object override = reflect(overrideBuilder, "build", new Class<?>[0]);

    Object builder = reflect(null, load(loader, clientInterface), "builder", new Class<?>[0]);
    Class<?> sdkBuilder = load(loader, "software.amazon.awssdk.core.client.builder.SdkClientBuilder");
    Class<?> awsBuilder = load(loader, "software.amazon.awssdk.awscore.client.builder.AwsClientBuilder");
    Class<?> regionType = load(loader, "software.amazon.awssdk.regions.Region");
    reflect(builder, sdkBuilder, "endpointOverride", new Class<?>[] { URI.class }, endpoint);
    reflect(builder, sdkBuilder, "overrideConfiguration", new Class<?>[] { overrideType }, override);
    reflect(
      builder,
      awsBuilder,
      "region",
      new Class<?>[] { regionType },
      reflect(null, regionType, "of", new Class<?>[] { String.class }, region)
    );
    reflect(
      builder,
      awsBuilder,
      "credentialsProvider",
      new Class<?>[] { load(loader, "software.amazon.awssdk.auth.credentials.AwsCredentialsProvider") },
      credentialsProvider
    );
    Object client = reflect(builder, load(loader, "software.amazon.awssdk.utils.builder.SdkBuilder"), "build", new Class<?>[0]);
    synchronized (this) {
      clients.add(client);
    }
    return client;
  }

  private static Class<?> load(ClassLoader loader, String name) {
    try {
      return Class.forName(name, true, loader);
    } catch (ClassNotFoundException e) {
      throw new IllegalStateException(e);
    }
  }

  private static Object reflect(Object target, String name, Class<?>[] types, Object... args) {
    return reflect(target, target.getClass(), name, types, args);
  }

  private static Object reflect(Object target, Class<?> type, String name, Class<?>[] types, Object... args) {
    try {
      Method method = type.getMethod(name, types);
      method.setAccessible(true);
      return method.invoke(target, args);
    } catch (InvocationTargetException e) {
      throw new IllegalStateException(e.getCause());
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(e);
    }
  }

  private void serve(HttpExchange exchange) throws IOException {
    try {
      byte[] requestBody = readAll(exchange.getRequestBody());
      String target = exchange.getRequestHeaders().getFirst("X-Amz-Target");
      boolean isKms = target != null && target.startsWith(KMS_TARGET_PREFIX);
      synchronized (this) {
        userAgents.add((isKms ? "kms: " : "dynamodb: ") + exchange.getRequestHeaders().getFirst("User-Agent"));
      }
      String contentType = isKms ? "application/x-amz-json-1.1" : "application/x-amz-json-1.0";
      JsonNode response;
      int status = 200;
      try {
        response = handle(exchange, target, isKms, requestBody);
      } catch (ServiceError e) {
        status = 400;
        response = e.body();
      } catch (RuntimeException e) {
        // A defect in the fake, not a modeled AWS error: surface it in the caller's exception.
        status = 500;
        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("__type", "InternalFailure");
        body.put("message", "fake AWS endpoint failed: " + e);
        response = body;
      }
      byte[] bytes = JSON.writeValueAsBytes(response);
      exchange.getResponseHeaders().set("Content-Type", contentType);
      exchange.getResponseHeaders().set("x-amzn-RequestId", nextRequestId());
      exchange.sendResponseHeaders(status, bytes.length);
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(bytes);
      }
    } finally {
      exchange.close();
    }
  }

  private synchronized String nextRequestId() {
    return String.format("00000000-0000-0000-0000-%012d", ++requestIds);
  }

  private synchronized JsonNode handle(HttpExchange exchange, String target, boolean isKms, byte[] requestBody) {
    String[] segments = exchange.getRequestURI().getPath().split("/");
    if (segments.length < 2 || !LABEL.matcher(segments[1]).matches()) {
      throw ServiceError.of("UnrecognizedClientException", "request path has no client label: " + exchange.getRequestURI());
    }
    String label = segments[1];
    String authorization = exchange.getRequestHeaders().getFirst("Authorization");
    Matcher scope = CREDENTIAL_SCOPE.matcher(authorization == null ? "" : authorization);
    if (!scope.find()) {
      throw ServiceError.of("MissingAuthenticationTokenException", "request is not SigV4-signed");
    }
    String region = scope.group(1);
    String service;
    String operation;
    if (isKms) {
      service = "kms";
      operation = target.substring(KMS_TARGET_PREFIX.length());
    } else if (target != null && target.startsWith(DYNAMODB_TARGET_PREFIX)) {
      service = "dynamodb";
      operation = target.substring(DYNAMODB_TARGET_PREFIX.length());
    } else {
      throw ServiceError.of("UnknownOperationException", "unknown X-Amz-Target: " + target);
    }
    if (!scope.group(2).equals(service)) {
      throw ServiceError.of("InvalidSignatureException", "signed for " + scope.group(2) + ", sent to " + service);
    }
    JsonNode body;
    try {
      body = requestBody.length == 0
        ? JsonNodeFactory.instance.objectNode()
        : JSON.readTree(new String(requestBody, StandardCharsets.UTF_8));
    } catch (IOException e) {
      throw ServiceError.of("SerializationException", "request body is not JSON: " + e.getMessage());
    }
    if (!body.isObject()) {
      throw ServiceError.of("SerializationException", "request body is not a JSON object");
    }
    requests.add(new RecordedRequest(label, service, operation, region, body));
    return isKms ? kms.handle(operation, region, (ObjectNode) body) : dynamoDb.handle(operation, region, (ObjectNode) body);
  }

  private static byte[] readAll(InputStream in) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] buffer = new byte[8192];
    int n;
    while ((n = in.read(buffer)) != -1) {
      out.write(buffer, 0, n);
    }
    return out.toByteArray();
  }
}
