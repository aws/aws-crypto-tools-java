// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.ClientSupplier;

/**
 * Encrypts and decrypts with KMS clients the caller builds for each request: one shared HTTP client, the request's
 * credentials, and source-context headers on every KMS call.
 *
 * <p>An MRK multi keyring gets its clients from a client supplier; a hierarchical keyring gets one through its key
 * store. The request's credentials are read from AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN;
 * DynamoDB calls use the default credentials.
 *
 * <p>Arguments: a multi-Region KMS key ARN, the ARN of its replica in another Region, and a key store's table name,
 * logical name, KMS key ARN, and existing branch key id.
 */
public final class KmsClientCustomizationExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private KmsClientCustomizationExample() {}

  public static void main(String[] args) {
    if (args.length != 6) {
      throw new IllegalArgumentException(
        "Arguments: <mrk-arn> <mrk-replica-arn> " +
        "<key-store-table> <logical-key-store-name> <kms-key-arn> <branch-key-id>"
      );
    }
    // Created once and shared, so every KMS and DynamoDB client below uses one connection pool.
    // An SDK client never closes an HTTP client it was given.
    try (
      SdkHttpClient httpClient = ApacheHttpClient.builder().build();
      DynamoDbClient ddbClient = DynamoDbClient.builder().httpClient(httpClient).build()
    ) {
      AwsCredentials credentials = credentialsForRequest();
      Map<String, String> headers = sourceContextHeaders();
      runMrkMultiKeyring(args[0], args[1], httpClient, credentials, headers);
      runHierarchicalKeyring(args[2], args[3], args[4], args[5], httpClient, ddbClient, credentials, headers);
    }
  }

  /** Encrypts with the multi-Region key in its Region, and decrypts with its replica in another. */
  public static void runMrkMultiKeyring(
    String mrkArn,
    String mrkReplicaArn,
    SdkHttpClient httpClient,
    AwsCredentials credentials,
    Map<String, String> headers
  ) {
    EsdkClient esdk = EsdkClient.create();
    Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // The keyrings ask the supplier for a client per Region, and never close clients from a supplier they were given.
    try (
      RequestClientSupplier clientSupplier = new RequestClientSupplier(httpClient, credentials, headers);
      AwsKmsMrkMultiKeyring encryptingKeyring = AwsKmsMrkMultiKeyring
        .builder()
        .generator(mrkArn)
        .clientSupplier(clientSupplier)
        .build();
      AwsKmsMrkMultiKeyring replicaKeyring = AwsKmsMrkMultiKeyring
        .builder()
        .generator(mrkReplicaArn)
        .clientSupplier(clientSupplier)
        .build()
    ) {
      byte[] ciphertext = esdk
        .encrypt(b -> b.plaintext(EXAMPLE_DATA).keyring(encryptingKeyring).encryptionContext(encryptionContext))
        .ciphertext();
      byte[] decrypted = esdk
        .decrypt(b -> b.ciphertext(ciphertext).keyring(replicaKeyring).encryptionContext(encryptionContext))
        .plaintext();
      if (!Arrays.equals(decrypted, EXAMPLE_DATA)) {
        throw new IllegalStateException("Decrypted plaintext does not match");
      }
    }
  }

  /** Encrypts and decrypts with a hierarchical keyring whose key store calls KMS with the request's client. */
  public static void runHierarchicalKeyring(
    String tableName,
    String logicalKeyStoreName,
    String kmsKeyArn,
    String branchKeyId,
    SdkHttpClient httpClient,
    DynamoDbClient ddbClient,
    AwsCredentials credentials,
    Map<String, String> headers
  ) {
    EsdkClient esdk = EsdkClient.create();
    try (
      KmsClient kmsClient = kmsClient(kmsKeyArn.split(":")[3], httpClient, credentials, headers);
      BranchKeyStore keyStore = BranchKeyStore
        .builder()
        .ddbTableName(tableName)
        .logicalKeyStoreName(logicalKeyStoreName)
        .kmsConfiguration(KmsConfiguration.kmsKeyArn(kmsKeyArn))
        .kmsClient(kmsClient)
        .ddbClient(ddbClient)
        .build()
    ) {
      // A keyring per request has its own cache, so a branch key fetched with one request's credentials
      // is never used for another request.
      Keyring keyring = AwsKmsHierarchicalKeyring
        .builder()
        .keyStore(keyStore)
        .branchKeyId(branchKeyId)
        .ttl(Duration.ofMinutes(5))
        .build();
      byte[] ciphertext = esdk.encrypt(b -> b.plaintext(EXAMPLE_DATA).keyring(keyring)).ciphertext();
      byte[] decrypted = esdk.decrypt(b -> b.ciphertext(ciphertext).keyring(keyring)).plaintext();
      if (!Arrays.equals(decrypted, EXAMPLE_DATA)) {
        throw new IllegalStateException("Decrypted plaintext does not match");
      }
    }
  }

  /** A KMS client for one request: the shared HTTP client, the request's credentials, and its headers. */
  static KmsClient kmsClient(
    String region,
    SdkHttpClient httpClient,
    AwsCredentials credentials,
    Map<String, String> headers
  ) {
    KmsClientBuilder builder = KmsClient
      .builder()
      .httpClient(httpClient)
      .credentialsProvider(StaticCredentialsProvider.create(credentials))
      .overrideConfiguration(o -> o.addExecutionInterceptor(new SourceContextHeaders(headers)));
    // A supplier is asked for "" when a key id or alias names no Region: that means the SDK's default Region.
    if (!region.isEmpty()) {
      builder.region(Region.of(region));
    }
    return builder.build();
  }

  /** Builds one client per Region on first use, and closes them all. */
  static final class RequestClientSupplier implements ClientSupplier, AutoCloseable {

    private final Map<String, KmsClient> clients = new ConcurrentHashMap<>();
    private final SdkHttpClient httpClient;
    private final AwsCredentials credentials;
    private final Map<String, String> headers;

    RequestClientSupplier(SdkHttpClient httpClient, AwsCredentials credentials, Map<String, String> headers) {
      this.httpClient = httpClient;
      this.credentials = credentials;
      this.headers = headers;
    }

    @Override
    public KmsClient getClient(String region) {
      return clients.computeIfAbsent(region, r -> kmsClient(r, httpClient, credentials, headers));
    }

    @Override
    public void close() {
      clients.values().forEach(KmsClient::close);
    }
  }

  /** Adds fixed headers to every request of the client it is registered on. */
  static final class SourceContextHeaders implements ExecutionInterceptor {

    private final Map<String, String> headers;

    SourceContextHeaders(Map<String, String> headers) {
      this.headers = headers;
    }

    // Runs before signing, so SigV4 signs the headers too.
    @Override
    public SdkHttpRequest modifyHttpRequest(
      Context.ModifyHttpRequest context,
      ExecutionAttributes executionAttributes
    ) {
      SdkHttpRequest.Builder request = context.httpRequest().toBuilder();
      headers.forEach(request::putHeader);
      return request.build();
    }
  }

  /** Stands in for the credentials a service receives with each request. */
  static AwsCredentials credentialsForRequest() {
    String accessKeyId = System.getenv("AWS_ACCESS_KEY_ID");
    String secretAccessKey = System.getenv("AWS_SECRET_ACCESS_KEY");
    String sessionToken = System.getenv("AWS_SESSION_TOKEN");
    if (accessKeyId == null || secretAccessKey == null) {
      throw new IllegalStateException("Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY");
    }
    return sessionToken == null
      ? AwsBasicCredentials.create(accessKeyId, secretAccessKey)
      : AwsSessionCredentials.create(accessKeyId, secretAccessKey, sessionToken);
  }

  /** Stands in for the source context a service receives with each request. */
  static Map<String, String> sourceContextHeaders() {
    Map<String, String> headers = new HashMap<>();
    headers.put("x-example-source-account", "111122223333");
    headers.put("x-example-source-arn", "arn:aws:example:us-west-2:111122223333:resource/example");
    return headers;
  }
}
