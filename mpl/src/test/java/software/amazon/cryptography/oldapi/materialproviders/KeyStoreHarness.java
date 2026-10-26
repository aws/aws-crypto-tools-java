// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.fakeaws.RecordedRequest;
import software.amazon.cryptography.oldapi.keystore.KeyStore;
import software.amazon.cryptography.oldapi.keystore.model.KMSConfiguration;
import software.amazon.cryptography.oldapi.keystore.model.KeyStoreConfig;

/**
 * Runs the native key store (through the test adapter) and the reference key store side by side.
 *
 * <p>Each side has its own {@link FakeAws}: {@link #nativeAws} and {@link #referenceAws}.
 * {@link #shared()} makes them the same endpoint, so both sides read the same items;
 * {@link #paired()} makes two endpoints that tests seed identically, so both sides can write the same items.
 * Native clients from {@link #kms}/{@link #ddb} talk to {@code nativeAws}; their reference twins to {@code referenceAws}.
 */
final class KeyStoreHarness implements AutoCloseable {

  static final String WEST = "us-west-2";
  static final String EAST = "us-east-1";
  static final String TABLE = "KeyStoreTable";
  static final String LOGICAL_NAME = "logical-key-store";
  static final List<String> GRANT_TOKENS = Arrays.asList("grant-token-a", "grant-token-b");

  // Random version 4 UUIDs, not the fake's deterministic key ids (00000000-0000-4000-8000-...).
  private static final Pattern RANDOM_UUID = Pattern.compile(
    "(?!00000000-0000-4000-8000-)[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
  );
  // The key store's timestamp format: milliseconds padded to six digits.
  private static final Pattern TIMESTAMP = Pattern.compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.0\\d{5}Z");
  private static final Pattern BYTES = Pattern.compile("0x[0-9a-f]+");
  // Identity hash codes in SDK messages, such as the region providers a failed lookup lists.
  private static final Pattern IDENTITY_HASH = Pattern.compile("([A-Za-z])@[0-9a-f]{1,8}\\b");
  // Hex from the fake; real DynamoDB ids are upper-case alphanumerics.
  private static final Pattern REQUEST_ID = Pattern.compile("Request ID: [0-9A-Za-z-]+");

  final FakeAws nativeAws;
  final FakeAws referenceAws;

  private KeyStoreHarness(FakeAws nativeAws, FakeAws referenceAws) {
    this.nativeAws = nativeAws;
    this.referenceAws = referenceAws;
  }

  static KeyStoreHarness shared() {
    FakeAws aws = FakeAws.start();
    return new KeyStoreHarness(aws, aws);
  }

  static KeyStoreHarness paired() {
    return new KeyStoreHarness(FakeAws.start(), FakeAws.start());
  }

  boolean isShared() {
    return nativeAws == referenceAws;
  }

  /** Both endpoints, once each, for seeding. */
  List<FakeAws> endpoints() {
    return isShared() ? Arrays.asList(nativeAws) : Arrays.asList(nativeAws, referenceAws);
  }

  /** A symmetric KMS key, created on each endpoint so both have the same ARN. */
  String symmetricKey(String region) {
    String arn = null;
    for (FakeAws aws : endpoints()) {
      arn = aws.kms().createSymmetricKey(region);
    }
    return arn;
  }

  /** A multi-Region key with replicas in {@code regions}, created on each endpoint. */
  List<String> multiRegionKey(String... regions) {
    List<String> arns = null;
    for (FakeAws aws : endpoints()) {
      arns = aws.kms().createMultiRegionKey(regions);
    }
    return arns;
  }

  KmsClient kms(String region) {
    KmsClient client = nativeAws.kmsClient(ReferenceAws.NATIVE, region);
    ReferenceMpl.registerTwin(client, referenceAws.kmsClient(ReferenceMpl.loader(), ReferenceAws.REFERENCE, region));
    return client;
  }

  DynamoDbClient ddb(String region) {
    DynamoDbClient client = nativeAws.dynamoDbClient(ReferenceAws.NATIVE, region);
    ReferenceMpl.registerTwin(client, referenceAws.dynamoDbClient(ReferenceMpl.loader(), ReferenceAws.REFERENCE, region));
    return client;
  }

  /** Decides the result of an intercepted call. */
  @FunctionalInterface
  interface Hook {
    /**
     * @param number the call number of this client, from 1
     * @param request the request, an SDK object of the calling side
     * @param proceed sends {@code request}
     */
    Object call(int number, Object request, Supplier<Object> proceed);
  }

  /**
   * A KMS client whose calls of {@code method} go through {@code hook}; its twin goes through the same hook.
   * The hook receives and returns each side's own SDK objects.
   */
  KmsClient kms(String region, String method, Hook hook) {
    return (KmsClient) intercepted(kms(region), KmsClient.class.getName(), method, hook);
  }

  /** As {@link #kms(String, String, BiFunction)}, for DynamoDB. */
  DynamoDbClient ddb(String region, String method, Hook hook) {
    return (DynamoDbClient) intercepted(ddb(region), DynamoDbClient.class.getName(), method, hook);
  }

  private static Object intercepted(Object client, String interfaceName, String method, Hook hook) {
    Object twin = ReferenceMpl.toReference(client);
    Object nativeProxy = intercept(client, interfaceName, method, hook);
    ReferenceMpl.registerTwin(nativeProxy, intercept(twin, interfaceName, method, hook));
    return nativeProxy;
  }

  private static Object intercept(Object client, String interfaceName, String method, Hook hook) {
    ClassLoader loader = client.getClass().getClassLoader();
    Class<?> type;
    try {
      type = Class.forName(interfaceName, true, loader);
    } catch (ClassNotFoundException e) {
      throw new IllegalStateException(e);
    }
    AtomicInteger calls = new AtomicInteger();
    return Proxy.newProxyInstance(
      loader,
      new Class<?>[] { type },
      (proxy, invoked, args) -> {
        if (!invoked.getName().equals(method)) {
          return invoke(invoked, client, args);
        }
        Object request = args[0];
        Method requestMethod = invoked;
        // A Consumer overload builds the request and calls the request overload; build it here so both count once.
        if (request instanceof Consumer) {
          requestMethod = requestOverload(type, method);
          Object builder = invoke(requestMethod.getParameterTypes()[0].getMethod("builder"), null, new Object[0]);
          @SuppressWarnings("unchecked")
          Consumer<Object> consumer = (Consumer<Object>) request;
          consumer.accept(builder);
          request = invoke(publicMethod(builder.getClass(), "build"), builder, new Object[0]);
        }
        Method target = requestMethod;
        Object[] targetArgs = { request };
        return hook.call(calls.incrementAndGet(), request, () -> invoke(target, client, targetArgs));
      }
    );
  }

  private static Method requestOverload(Class<?> type, String name) {
    for (Method candidate : type.getMethods()) {
      if (
        candidate.getName().equals(name) &&
        candidate.getParameterCount() == 1 &&
        !Consumer.class.isAssignableFrom(candidate.getParameterTypes()[0])
      ) {
        return candidate;
      }
    }
    throw new IllegalArgumentException("no request overload of " + name);
  }

  private static Method publicMethod(Class<?> type, String name) throws NoSuchMethodException {
    Method method = type.getMethod(name);
    method.setAccessible(true);
    return method;
  }

  private static Object invoke(Method method, Object target, Object[] args) {
    try {
      method.setAccessible(true);
      return method.invoke(target, args);
    } catch (InvocationTargetException e) {
      if (e.getCause() instanceof RuntimeException) {
        throw (RuntimeException) e.getCause();
      }
      throw new IllegalStateException(e.getCause());
    } catch (IllegalAccessException e) {
      throw new IllegalStateException(e);
    }
  }

  /** {@code model.toBuilder().<field>(value).build()} for an SDK model object of either side. */
  static Object with(Object model, String field, Object value) {
    try {
      Object builder = model.getClass().getMethod("toBuilder").invoke(model);
      for (Method method : builder.getClass().getMethods()) {
        if (method.getName().equals(field) && method.getParameterCount() == 1 && accepts(method, value)) {
          method.setAccessible(true);
          method.invoke(builder, value);
          Method build = builder.getClass().getMethod("build");
          build.setAccessible(true);
          return build.invoke(builder);
        }
      }
      throw new IllegalArgumentException("no setter " + field + " on " + builder.getClass().getName());
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(e);
    }
  }

  private static boolean accepts(Method method, Object value) {
    Class<?> parameter = method.getParameterTypes()[0];
    return value == null ? !parameter.isPrimitive() && !parameter.getName().startsWith("java.util.function") : parameter.isInstance(value);
  }

  /** {@code SdkBytes.fromByteArray(bytes)} from the SDK copy that loaded {@code model}. */
  static Object sdkBytes(Object model, byte[] bytes) {
    try {
      Class<?> type = Class.forName(SdkBytes.class.getName(), true, model.getClass().getClassLoader());
      return type.getMethod("fromByteArray", byte[].class).invoke(null, (Object) bytes);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(e);
    }
  }

  /** {@code item} rebuilt with the DynamoDB SDK copy that loaded {@code model}. Supports S, N, B, BOOL, NULL, and SS. */
  static Object attributeMap(Object model, Map<String, AttributeValue> item) {
    ClassLoader loader = model.getClass().getClassLoader();
    if (loader == AttributeValue.class.getClassLoader()) {
      return item;
    }
    try {
      Class<?> type = Class.forName(AttributeValue.class.getName(), true, loader);
      Map<String, Object> converted = new HashMap<>();
      for (Map.Entry<String, AttributeValue> entry : item.entrySet()) {
        AttributeValue value = entry.getValue();
        Object builder = publicMethod(type, "builder").invoke(null);
        switch (value.type()) {
          case S:
            set(builder, "s", String.class, value.s());
            break;
          case N:
            set(builder, "n", String.class, value.n());
            break;
          case B:
            set(builder, "b", sdkBytes(model, new byte[0]).getClass(), sdkBytes(model, value.b().asByteArray()));
            break;
          case BOOL:
            set(builder, "bool", Boolean.class, value.bool());
            break;
          case NUL:
            set(builder, "nul", Boolean.class, value.nul());
            break;
          case SS:
            set(builder, "ss", java.util.Collection.class, value.ss());
            break;
          default:
            throw new IllegalArgumentException("unsupported attribute type " + value.type());
        }
        converted.put(entry.getKey(), publicMethod(builder.getClass(), "build").invoke(builder));
      }
      return converted;
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(e);
    }
  }

  private static void set(Object builder, String name, Class<?> parameter, Object value) throws ReflectiveOperationException {
    Method method = builder.getClass().getMethod(name, parameter);
    method.setAccessible(true);
    method.invoke(builder, value);
  }

  /** {@code model.<accessor>()} for an SDK model object of either side. */
  static Object get(Object model, String accessor) {
    try {
      Method method = model.getClass().getMethod(accessor);
      method.setAccessible(true);
      return method.invoke(model);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(e);
    }
  }

  static KeyStoreConfig.Builder config(KMSConfiguration kmsConfiguration, KmsClient kms, DynamoDbClient ddb) {
    return KeyStoreConfig.builder()
      .ddbTableName(TABLE)
      .logicalKeyStoreName(LOGICAL_NAME)
      .kmsConfiguration(kmsConfiguration)
      .grantTokens(GRANT_TOKENS)
      .kmsClient(kms)
      .ddbClient(ddb);
  }

  static KMSConfiguration keyArn(String arn) {
    return KMSConfiguration.builder().kmsKeyArn(arn).build();
  }

  static KMSConfiguration mrKeyArn(String arn) {
    return KMSConfiguration.builder().kmsMRKeyArn(arn).build();
  }

  static KMSConfiguration discovery() {
    return KMSConfiguration.builder().discovery(software.amazon.cryptography.oldapi.keystore.model.Discovery.builder().build()).build();
  }

  static KMSConfiguration mrDiscovery(String region) {
    return KMSConfiguration.builder()
      .mrDiscovery(software.amazon.cryptography.oldapi.keystore.model.MRDiscovery.builder().region(region).build())
      .build();
  }

  static KeyStore nativeStore(KeyStoreConfig config) {
    return KeyStore.builder().KeyStoreConfig(config).build();
  }

  static Object referenceStore(KeyStoreConfig config) {
    return ReferenceMpl.keyStore(config);
  }

  /** Both sides' stores for {@code config}; either may be the failure of building it. */
  static Stores stores(KeyStoreConfig config) {
    return new Stores(config, false);
  }

  /** As {@link #stores}, for paired endpoints: each side's keys are its own, so outcomes are compared with key bytes masked. */
  static Stores pairedStores(KeyStoreConfig config) {
    return new Stores(config, true);
  }

  /** The adapter and reference stores for one config, and the outcomes of building them. */
  static final class Stores {

    final KeyStore nativeStore;
    final Object referenceStore;
    final String nativeBuild;
    final String referenceBuild;
    private final boolean maskKeys;

    Stores(KeyStoreConfig config, boolean maskKeys) {
      this.maskKeys = maskKeys;
      KeyStore[] built = new KeyStore[1];
      Object[] reference = new Object[1];
      nativeBuild = outcome(() -> {
        built[0] = nativeStore(config);
        return null;
      });
      referenceBuild = outcome(() -> {
        reference[0] = referenceStore(config);
        return null;
      });
      assertEquals(referenceBuild, nativeBuild, "building the key store");
      nativeStore = built[0];
      referenceStore = reference[0];
    }

    /** Runs the operation on both sides and requires the same outcome; returns it. */
    String same(String operation, Object input) {
      return same(operation, input, input);
    }

    /** As {@link #same(String, Object)}, with each side's own input, such as a version only that side created. */
    String same(String operation, Object nativeInput, Object referenceInput) {
      String nativeOutcome = outcome(() -> nativeCall(nativeStore, operation, nativeInput));
      String referenceOutcome = outcome(() ->
        referenceInput == null ? ReferenceMpl.call(referenceStore, operation) : ReferenceMpl.call(referenceStore, operation, referenceInput)
      );
      if (maskKeys) {
        nativeOutcome = BYTES.matcher(nativeOutcome).replaceAll("0x<bytes>");
        referenceOutcome = BYTES.matcher(referenceOutcome).replaceAll("0x<bytes>");
      }
      assertEquals(referenceOutcome, nativeOutcome, operation);
      return nativeOutcome;
    }
  }

  static Object nativeCall(KeyStore store, String operation, Object input) {
    for (Method method : KeyStore.class.getMethods()) {
      if (method.getName().equals(operation)) {
        return invoke(method, store, input == null ? new Object[0] : new Object[] { input });
      }
    }
    throw new IllegalArgumentException(operation);
  }

  /** {@link ReferenceMpl#outcome} with the random values masked: UUIDs, timestamps, and request ids. */
  static String outcome(Supplier<Object> call) {
    return mask(ReferenceMpl.outcome(call));
  }

  static String mask(String text) {
    String masked = RANDOM_UUID.matcher(text).replaceAll("<uuid>");
    masked = TIMESTAMP.matcher(masked).replaceAll("<time>");
    masked = IDENTITY_HASH.matcher(masked).replaceAll("$1@<hash>");
    return REQUEST_ID.matcher(masked).replaceAll("Request ID: <id>");
  }

  /** The requests one side sent, described with the random values masked and wrapped keys dropped. */
  List<String> requests(String label) {
    FakeAws aws = label.equals(ReferenceAws.NATIVE) ? nativeAws : referenceAws;
    List<String> described = new ArrayList<>();
    for (RecordedRequest request : aws.requests(label)) {
      described.add(mask(request.describe("CiphertextBlob", "enc")));
    }
    return described;
  }

  /** Both sides sent the same requests, apart from random values. */
  void assertSameRequests() {
    assertEquals(requests(ReferenceAws.REFERENCE), requests(ReferenceAws.NATIVE));
  }

  void clearRequests() {
    for (FakeAws aws : endpoints()) {
      aws.clearRequests();
    }
  }

  /** Creates the key store table on each endpoint, with a setup client whose requests are not compared. */
  void createTable(String region) {
    for (FakeAws aws : endpoints()) {
      aws.dynamoDbClient("setup", region).createTable(r ->
        r
          .tableName(TABLE)
          .billingMode("PAY_PER_REQUEST")
          .keySchema(
            KeySchemaElement.builder().attributeName("branch-key-id").keyType("HASH").build(),
            KeySchemaElement.builder().attributeName("type").keyType("RANGE").build()
          )
          .attributeDefinitions(
            AttributeDefinition.builder().attributeName("branch-key-id").attributeType("S").build(),
            AttributeDefinition.builder().attributeName("type").attributeType("S").build()
          )
      );
    }
  }

  /** Stores {@code item} on each endpoint. */
  void putItem(String region, Map<String, AttributeValue> item) {
    for (FakeAws aws : endpoints()) {
      aws.dynamoDbClient("setup", region).putItem(r -> r.tableName(TABLE).item(item));
    }
  }

  /** The item stored under a key on the native endpoint, or an empty map. */
  Map<String, AttributeValue> item(String region, String branchKeyIdentifier, String type) {
    Map<String, AttributeValue> key = new HashMap<>();
    key.put("branch-key-id", AttributeValue.builder().s(branchKeyIdentifier).build());
    key.put("type", AttributeValue.builder().s(type).build());
    return nativeAws.dynamoDbClient("setup", region).getItem(r -> r.tableName(TABLE).key(key)).item();
  }

  @Override
  public void close() {
    for (FakeAws aws : endpoints()) {
      aws.close();
    }
  }
}
