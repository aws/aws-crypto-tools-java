// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.KeyringTests.Outcomes;
import software.amazon.cryptography.materialproviders.KmsKeyringTests.Supplied;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.DBEAlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.ESDKAlgorithmSuiteId;

/**
 * Real AWS clients for the integration tests: a native client per Region and service,
 * and its twin from the reference MPL's copy of the AWS SDK, with the same profile and Region.
 *
 * <p>The resources are KEY=VALUE lines in the file named by MPL_IT_RESOURCES;
 * an environment variable MPL_IT_KEY overrides a line.
 * Keys: SYM (symmetric), MRK and MRK_REPLICA (a multi-Region key and its replica in another Region),
 * RSA (RSA_2048, ENCRYPT_DECRYPT), ECC (ECC_NIST_P256, KEY_AGREEMENT).
 */
final class RealAws implements AutoCloseable {

  /** The only table the tests may create; {@code createKeyStore} creates it on first use. */
  static final String TABLE = "mpl-native-java-it-keystore";
  static final String LOGICAL_NAME = "mpl-native-java-it";
  static final String OTHER_ACCOUNT = "111122223333";

  static final AlgorithmSuiteId NON_COMMITTING = AlgorithmSuiteId.builder().ESDK(ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256).build();
  static final AlgorithmSuiteId COMMITTING_SIGNING = AlgorithmSuiteId
    .builder()
    .ESDK(ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384)
    .build();
  static final AlgorithmSuiteId DBE = AlgorithmSuiteId.builder().DBE(DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384).build();
  /** One ESDK non-committing suite, one ESDK committing and signing suite, one DB-ESDK suite. */
  static final List<AlgorithmSuiteId> SUITES = Arrays.asList(NON_COMMITTING, COMMITTING_SIGNING, DBE);

  final String profile;
  final String sym;
  final String mrk;
  final String mrkReplica;
  final String rsa;
  final String ecc;
  final String region;
  final String replicaRegion;
  final String account;

  private final Map<String, KmsClient> kmsClients = new HashMap<>();
  private final Map<String, DynamoDbClient> ddbClients = new HashMap<>();
  private final List<Object> built = new ArrayList<>();

  private RealAws(String profile, Map<String, String> resources) {
    this.profile = profile;
    sym = required(resources, "SYM");
    mrk = required(resources, "MRK");
    mrkReplica = required(resources, "MRK_REPLICA");
    rsa = required(resources, "RSA");
    ecc = required(resources, "ECC");
    region = arnPart(sym, 3);
    replicaRegion = arnPart(mrkReplica, 3);
    account = arnPart(sym, 4);
    for (String arn : Arrays.asList(mrk, rsa, ecc)) {
      assertEquals(region, arnPart(arn, 3), "every key but the replica is in the Region of SYM: " + arn);
    }
    for (String arn : Arrays.asList(mrk, mrkReplica, rsa, ecc)) {
      assertEquals(account, arnPart(arn, 4), "every key is in the account of SYM: " + arn);
    }
    assertNotEquals(region, replicaRegion, "the replica is in another Region");
  }

  static RealAws fromEnvironment() {
    String profile = System.getenv("MPL_IT_PROFILE");
    String file = System.getenv("MPL_IT_RESOURCES");
    if (profile == null) {
      throw new IllegalStateException("MPL_IT_PROFILE is not set");
    }
    Map<String, String> resources = new LinkedHashMap<>();
    if (file != null) {
      try {
        for (String line : Files.readAllLines(Paths.get(file), StandardCharsets.UTF_8)) {
          int equals = line.indexOf('=');
          if (equals > 0 && !line.trim().startsWith("#")) {
            resources.put(line.substring(0, equals).trim(), line.substring(equals + 1).trim());
          }
        }
      } catch (IOException e) {
        throw new IllegalStateException("cannot read MPL_IT_RESOURCES " + file, e);
      }
    }
    for (Map.Entry<String, String> variable : System.getenv().entrySet()) {
      if (variable.getKey().startsWith("MPL_IT_") && !variable.getKey().equals("MPL_IT_PROFILE") && !variable.getKey().equals("MPL_IT_RESOURCES")) {
        resources.put(variable.getKey().substring("MPL_IT_".length()), variable.getValue());
      }
    }
    return new RealAws(profile, resources);
  }

  private static String required(Map<String, String> resources, String key) {
    String value = resources.get(key);
    if (value == null || value.isEmpty()) {
      throw new IllegalStateException("no " + key + " in MPL_IT_RESOURCES or MPL_IT_" + key);
    }
    return value;
  }

  /** Field {@code index} of {@code arn:partition:service:region:account:resource}. */
  static String arnPart(String arn, int index) {
    return arn.split(":", 6)[index];
  }

  /** The key id: the part of the ARN after {@code key/}. */
  static String keyId(String arn) {
    return arn.substring(arn.indexOf("key/") + 4);
  }

  /** The native KMS client for {@code region}, its reference twin registered; one per Region. */
  synchronized KmsClient kms(String region) {
    return kmsClients.computeIfAbsent(region, r -> {
      KmsClient client = (KmsClient) client(RealAws.class.getClassLoader(), KmsClient.class.getName(), r);
      ReferenceMpl.registerTwin(client, client(ReferenceMpl.loader(), KmsClient.class.getName(), r));
      return client;
    });
  }

  /** The native DynamoDB client for {@code region}, its reference twin registered; one per Region. */
  synchronized DynamoDbClient dynamoDb(String region) {
    return ddbClients.computeIfAbsent(region, r -> {
      DynamoDbClient client = (DynamoDbClient) client(RealAws.class.getClassLoader(), DynamoDbClient.class.getName(), r);
      ReferenceMpl.registerTwin(client, client(ReferenceMpl.loader(), DynamoDbClient.class.getName(), r));
      return client;
    });
  }

  /** A new native KMS client for {@code region}, with no twin, for code that may close it; {@link #close} closes it too. */
  KmsClient newKms(String region) {
    return (KmsClient) client(RealAws.class.getClassLoader(), KmsClient.class.getName(), region);
  }

  /** A client supplier for both sides that returns {@link #kms(String)}; each side's calls are recorded. */
  Supplied supplier() {
    return new Supplied(input -> kms(input.region()));
  }

  // Built by reflection so one code path configures both SDK copies the same way.
  private Object client(ClassLoader loader, String clientInterface, String region) {
    Class<?> providerType = load(loader, "software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider");
    Object credentials = reflect(null, providerType, "create", new Class<?>[] { String.class }, profile);
    Object builder = reflect(null, load(loader, clientInterface), "builder", new Class<?>[0]);
    Class<?> awsBuilder = load(loader, "software.amazon.awssdk.awscore.client.builder.AwsClientBuilder");
    Class<?> regionType = load(loader, "software.amazon.awssdk.regions.Region");
    reflect(builder, awsBuilder, "region", new Class<?>[] { regionType }, reflect(null, regionType, "of", new Class<?>[] { String.class }, region));
    reflect(
      builder,
      awsBuilder,
      "credentialsProvider",
      new Class<?>[] { load(loader, "software.amazon.awssdk.auth.credentials.AwsCredentialsProvider") },
      credentials
    );
    Object client = reflect(builder, load(loader, "software.amazon.awssdk.utils.builder.SdkBuilder"), "build", new Class<?>[0]);
    synchronized (this) {
      built.add(client);
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

  @Override
  public synchronized void close() {
    for (Object client : built) {
      reflect(client, client.getClass(), "close", new Class<?>[0]);
    }
    built.clear();
    kmsClients.clear();
    ddbClients.clear();
  }

  /**
   * Runs one operation on each side and asserts the same outcome, request ids masked; returns it.
   * Unlike the fake-AWS tests, the requests sent are not compared: the real endpoints do not record them.
   */
  static String assertSame(Outcomes outcomes, String operation, Supplier<Object> reference, Supplier<Object> nativeCall, String context) {
    String expected = KmsKeyringTests.normalized(ReferenceMpl.outcome(reference));
    String actual = KmsKeyringTests.normalized(ReferenceMpl.outcome(nativeCall));
    assertEquals(expected, actual, context);
    // The run's output shows what the real services answered; the report compares it with the fake.
    System.out.println("compared " + operation + (actual.startsWith("throws") ? " " + abbreviated(actual, 2000) + " | " + abbreviated(context, 200) : " returns"));
    return outcomes.record(operation, actual);
  }

  private static String abbreviated(String text, int length) {
    return text.length() <= length ? text : text.substring(0, length) + "...";
  }
}
