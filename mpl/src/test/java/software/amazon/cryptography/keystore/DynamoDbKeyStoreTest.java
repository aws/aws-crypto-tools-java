// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.keystore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.TransactionCanceledException;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.exceptions.AccessDeniedException;
import software.amazon.cryptography.materialproviders.exceptions.ConflictException;
import software.amazon.cryptography.materialproviders.exceptions.DispatchException;
import software.amazon.cryptography.materialproviders.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.materialproviders.exceptions.MaterialProvidersException;
import software.amazon.cryptography.materialproviders.exceptions.ResourceNotFoundException;
import software.amazon.cryptography.materialproviders.exceptions.ServiceException;
import software.amazon.cryptography.materialproviders.exceptions.ThrottlingException;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.fakeaws.ServiceError;
import software.amazon.cryptography.materialproviders.internal.KeyMaterialsAccess;

// The native API: exception kinds and causes, value semantics, and argument checks.
// Behavior against the reference is covered through the test adapter in oldapi.materialproviders.KeyStore*Test.
class DynamoDbKeyStoreTest {

  private static final String REGION = "us-west-2";
  private static final String TABLE = "KeyStoreTable";

  private final FakeAws aws = FakeAws.start();
  private final String kmsKey = aws.kms().createSymmetricKey(REGION);
  private final KmsClient kms = aws.kmsClient("native", REGION);
  private final DynamoDbClient ddb = aws.dynamoDbClient("native", REGION);

  @AfterEach
  void close() {
    aws.close();
  }

  private DynamoDbKeyStore.Builder builder(KmsConfiguration configuration) {
    return DynamoDbKeyStore.builder()
      .ddbTableName(TABLE)
      .logicalKeyStoreName("logical")
      .kmsConfiguration(configuration)
      .kmsClient(kms)
      .ddbClient(ddb);
  }

  private DynamoDbKeyStore store() {
    DynamoDbKeyStore store = builder(KmsConfiguration.kmsKeyArn(kmsKey)).build();
    store.createKeyStore();
    return store;
  }

  @Test
  void builderRequiresTheTableLogicalNameAndConfiguration() {
    assertEquals(
      "Missing value for required field `ddbTableName`",
      assertThrows(ValidationException.class, () -> DynamoDbKeyStore.builder().build()).getMessage()
    );
    assertEquals(
      "Missing value for required field `kmsConfiguration`",
      assertThrows(ValidationException.class, () -> DynamoDbKeyStore.builder().ddbTableName(TABLE).build()).getMessage()
    );
    assertEquals(
      "Missing value for required field `logicalKeyStoreName`",
      assertThrows(
        ValidationException.class,
        () -> DynamoDbKeyStore.builder().ddbTableName(TABLE).kmsConfiguration(KmsConfiguration.discovery()).build()
      ).getMessage()
    );
    assertEquals(
      "Invalid Amazon DynamoDB Table Name",
      assertThrows(ValidationException.class, () -> builder(KmsConfiguration.discovery()).ddbTableName("ab").build()).getMessage()
    );
    assertEquals(
      "Invalid Amazon DynamoDB Table Name",
      assertThrows(ValidationException.class, () -> builder(KmsConfiguration.discovery()).ddbTableName(repeat('t', 256)).build())
        .getMessage()
    );
    builder(KmsConfiguration.discovery()).ddbTableName("abc").build();
    builder(KmsConfiguration.discovery()).ddbTableName(repeat('t', 255)).build();
    assertThrows(NullPointerException.class, () -> builder(KmsConfiguration.discovery()).grantTokens(Arrays.asList("a", null)));
  }

  @Test
  void keyStoreInfo() {
    List<String> tokens = new ArrayList<>(Arrays.asList("t1", "t2"));
    DynamoDbKeyStore store = builder(KmsConfiguration.kmsKeyArn(kmsKey)).id("store-id").grantTokens(tokens).build();
    tokens.add("added later");
    GetKeyStoreInfoResponse info = store.getKeyStoreInfo();
    assertEquals("store-id", info.keyStoreId());
    assertEquals(TABLE, info.keyStoreName());
    assertEquals("logical", info.logicalKeyStoreName());
    assertEquals(Arrays.asList("t1", "t2"), info.grantTokens());
    assertThrows(UnsupportedOperationException.class, () -> info.grantTokens().add("x"));
    assertEquals(KmsConfiguration.kmsKeyArn(kmsKey), info.kmsConfiguration());
    assertEquals(info, builder(KmsConfiguration.kmsKeyArn(kmsKey)).id("store-id").grantTokens(Arrays.asList("t1", "t2")).build().getKeyStoreInfo());
    assertEquals(info.hashCode(), builder(KmsConfiguration.kmsKeyArn(kmsKey)).id("store-id").grantTokens(Arrays.asList("t1", "t2")).build().getKeyStoreInfo().hashCode());
    assertNotEquals(info, builder(KmsConfiguration.kmsKeyArn(kmsKey)).id("other").grantTokens(Arrays.asList("t1", "t2")).build().getKeyStoreInfo());
    assertNotEquals(info, builder(KmsConfiguration.kmsKeyArn(kmsKey)).id("store-id").build().getKeyStoreInfo());
    assertNotEquals(info, builder(KmsConfiguration.discovery()).id("store-id").grantTokens(Arrays.asList("t1", "t2")).build().getKeyStoreInfo());
    assertNotEquals(info, builder(KmsConfiguration.kmsKeyArn(kmsKey)).id("store-id").ddbTableName("Other").grantTokens(Arrays.asList("t1", "t2")).build().getKeyStoreInfo());
    assertNotEquals(info, builder(KmsConfiguration.kmsKeyArn(kmsKey)).id("store-id").logicalKeyStoreName("x").grantTokens(Arrays.asList("t1", "t2")).build().getKeyStoreInfo());
    assertFalse(info.toString().contains("t1"), info.toString());
    assertTrue(info.toString().contains("store-id"), info.toString());
    assertTrue(builder(KmsConfiguration.discovery()).build().getKeyStoreInfo().keyStoreId().matches("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"));
  }

  @Test
  void kmsConfigurations() {
    String mrk = "arn:aws:kms:us-west-2:111122223333:key/mrk-1234";
    KmsConfiguration keyArn = KmsConfiguration.kmsKeyArn(kmsKey);
    assertEquals(KmsConfiguration.Kind.KMS_KEY_ARN, keyArn.kind());
    assertEquals(Optional.of(kmsKey), keyArn.arn());
    assertEquals(Optional.empty(), keyArn.region());
    KmsConfiguration mrKeyArn = KmsConfiguration.kmsMrKeyArn(mrk);
    assertEquals(KmsConfiguration.Kind.KMS_MR_KEY_ARN, mrKeyArn.kind());
    assertEquals(Optional.of(mrk), mrKeyArn.arn());
    KmsConfiguration discovery = KmsConfiguration.discovery();
    assertEquals(KmsConfiguration.Kind.DISCOVERY, discovery.kind());
    assertEquals(Optional.empty(), discovery.arn());
    assertEquals(Optional.empty(), discovery.region());
    KmsConfiguration mrDiscovery = KmsConfiguration.mrDiscovery("eu-west-1");
    assertEquals(KmsConfiguration.Kind.MR_DISCOVERY, mrDiscovery.kind());
    assertEquals(Optional.of("eu-west-1"), mrDiscovery.region());
    assertEquals(Optional.empty(), mrDiscovery.arn());

    assertEquals(discovery, KmsConfiguration.discovery());
    assertEquals(mrDiscovery, KmsConfiguration.mrDiscovery("eu-west-1"));
    assertEquals(mrDiscovery.hashCode(), KmsConfiguration.mrDiscovery("eu-west-1").hashCode());
    assertNotEquals(mrDiscovery, KmsConfiguration.mrDiscovery("eu-west-2"));
    assertNotEquals(KmsConfiguration.kmsKeyArn(mrk), KmsConfiguration.kmsMrKeyArn(mrk));
    assertNotEquals(keyArn, KmsConfiguration.kmsKeyArn(mrk));
    assertTrue(keyArn.toString().contains(kmsKey) && keyArn.toString().contains("KMS_KEY_ARN"), keyArn.toString());
    assertTrue(mrDiscovery.toString().contains("eu-west-1"), mrDiscovery.toString());
    assertEquals("KmsConfiguration[DISCOVERY]", discovery.toString());

    assertEquals(
      "Key Store encountered a KMS Alias ARN instead of a KMS Key ARN, which is not allowed.",
      assertThrows(ValidationException.class, () -> KmsConfiguration.kmsKeyArn("arn:aws:kms:us-west-2:111122223333:alias/a")).getMessage()
    );
    assertEquals(
      "KMSConfiguration's KMS Key ARN is invalid.",
      assertThrows(ValidationException.class, () -> KmsConfiguration.kmsMrKeyArn("")).getMessage()
    );
    assertEquals(
      "The size of `region` must be greater than or equal to 1",
      assertThrows(ValidationException.class, () -> KmsConfiguration.mrDiscovery("")).getMessage()
    );
    assertEquals(
      "The size of `region` must be less than or equal to 32",
      assertThrows(ValidationException.class, () -> KmsConfiguration.mrDiscovery(repeat('r', 33))).getMessage()
    );
    KmsConfiguration.mrDiscovery(repeat('r', 32));
    assertThrows(NullPointerException.class, () -> KmsConfiguration.kmsKeyArn(null));
    assertThrows(NullPointerException.class, () -> KmsConfiguration.mrDiscovery(null));
  }

  @Test
  void materials() {
    DynamoDbKeyStore store = store();
    String id = store.createKey(b -> b.branchKeyIdentifier("branch").encryptionContext(EncryptionContext.of("tenant", "a"))).branchKeyIdentifier();
    BranchKeyMaterials active = store.getActiveBranchKey(GetActiveBranchKeyRequest.builder().branchKeyIdentifier(id).build()).branchKeyMaterials();
    assertEquals("branch", active.branchKeyIdentifier());
    assertEquals(EncryptionContext.of("tenant", "a"), active.encryptionContext());
    assertEquals(32, active.branchKey().length());
    BranchKeyMaterials sameVersion = store.getBranchKeyVersion(GetBranchKeyVersionRequest.builder().branchKeyIdentifier(id).branchKeyVersion(active.branchKeyVersion()).build()).branchKeyMaterials();
    assertEquals(active, sameVersion);
    assertEquals(active.hashCode(), sameVersion.hashCode());
    assertNotSame(active.branchKey(), sameVersion.branchKey());
    String text = active.toString();
    assertTrue(text.contains("branch") && text.contains(active.branchKeyVersion()) && text.contains("tenant"), text);
    assertFalse(text.contains("\"a\"") || text.contains("=a"), text);

    store.versionKey(VersionKeyRequest.builder().branchKeyIdentifier(id).build());
    BranchKeyMaterials next = store.getActiveBranchKey(GetActiveBranchKeyRequest.builder().branchKeyIdentifier(id).build()).branchKeyMaterials();
    assertNotEquals(active, next);
    assertNotEquals(active.branchKeyVersion(), next.branchKeyVersion());
    assertNotEquals(active, null);

    BeaconKeyMaterials beacon = store.getBeaconKey(GetBeaconKeyRequest.builder().branchKeyIdentifier(id).build()).beaconKeyMaterials();
    assertEquals("branch", beacon.beaconKeyIdentifier());
    assertEquals(EncryptionContext.of("tenant", "a"), beacon.encryptionContext());
    assertTrue(beacon.beaconKey().isPresent());
    assertFalse(beacon.beaconKey().get().contentEquals(active.branchKey()));
    assertEquals(Collections.emptyMap(), beacon.hmacKeys());
    assertEquals(beacon, store.getBeaconKey(GetBeaconKeyRequest.builder().branchKeyIdentifier(id).build()).beaconKeyMaterials());
    assertEquals(beacon.hashCode(), store.getBeaconKey(GetBeaconKeyRequest.builder().branchKeyIdentifier(id).build()).beaconKeyMaterials().hashCode());
    assertTrue(beacon.toString().contains("branch") && beacon.toString().contains("tenant"), beacon.toString());

    // Random ids, and a custom context without an id.
    String random = store.createKey().branchKeyIdentifier();
    assertTrue(random.matches("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"), random);
    assertEquals(EncryptionContext.empty(), store.getActiveBranchKey(b -> b.branchKeyIdentifier(random)).branchKeyMaterials().encryptionContext());
    String withContext = store.createKey(b -> b.encryptionContext(EncryptionContext.of("k", "v"))).branchKeyIdentifier();
    assertEquals(EncryptionContext.of("k", "v"), store.getActiveBranchKey(b -> b.branchKeyIdentifier(withContext)).branchKeyMaterials().encryptionContext());
    assertNotEquals(store.getActiveBranchKey(b -> b.branchKeyIdentifier(random)).branchKeyMaterials(), store.getActiveBranchKey(b -> b.branchKeyIdentifier(withContext)).branchKeyMaterials());
  }

  @Test
  void materialsEquality() {
    byte[] key = new byte[32];
    byte[] otherKey = new byte[32];
    otherKey[0] = 1;
    EncryptionContext context = EncryptionContext.of("k", "v");
    BranchKeyMaterials branch = KeyMaterialsAccess.branchKey("id", "version", context, SecretBytes.copyOf(key));
    assertEquals(branch, KeyMaterialsAccess.branchKey("id", "version", EncryptionContext.of("k", "v"), SecretBytes.copyOf(key)));
    assertEquals(branch.hashCode(), KeyMaterialsAccess.branchKey("id", "version", context, SecretBytes.copyOf(key)).hashCode());
    assertNotEquals(branch, KeyMaterialsAccess.branchKey("other", "version", context, SecretBytes.copyOf(key)));
    assertNotEquals(branch, KeyMaterialsAccess.branchKey("id", "other", context, SecretBytes.copyOf(key)));
    assertNotEquals(branch, KeyMaterialsAccess.branchKey("id", "version", EncryptionContext.of("k", "w"), SecretBytes.copyOf(key)));
    assertNotEquals(branch, KeyMaterialsAccess.branchKey("id", "version", context, SecretBytes.copyOf(otherKey)));
    assertNotEquals(branch, "id");

    BeaconKeyMaterials beacon = KeyMaterialsAccess.beaconKey("id", context, SecretBytes.copyOf(key), java.util.Collections.emptyMap());
    assertEquals(beacon, KeyMaterialsAccess.beaconKey("id", EncryptionContext.of("k", "v"), SecretBytes.copyOf(key), java.util.Collections.emptyMap()));
    assertEquals(beacon.hashCode(), KeyMaterialsAccess.beaconKey("id", context, SecretBytes.copyOf(key), java.util.Collections.emptyMap()).hashCode());
    assertNotEquals(beacon, KeyMaterialsAccess.beaconKey("other", context, SecretBytes.copyOf(key), java.util.Collections.emptyMap()));
    assertNotEquals(beacon, KeyMaterialsAccess.beaconKey("id", EncryptionContext.empty(), SecretBytes.copyOf(key), java.util.Collections.emptyMap()));
    assertNotEquals(beacon, KeyMaterialsAccess.beaconKey("id", context, SecretBytes.copyOf(otherKey), java.util.Collections.emptyMap()));
    assertNotEquals(beacon, branch);
    assertFalse(branch.toString().contains("SecretBytes") && branch.toString().contains("00"), branch.toString());
  }

  @Test
  void failureKinds() {
    DynamoDbKeyStore store = store();
    store.createKey(b -> b.branchKeyIdentifier("taken").encryptionContext(EncryptionContext.of("k", "v")));

    ConflictException conflict = assertThrows(ConflictException.class, () -> store.createKey(b -> b.branchKeyIdentifier("taken").encryptionContext(EncryptionContext.of("k", "v"))));
    assertInstanceOf(TransactionCanceledException.class, conflict.getCause());
    assertEquals(conflict.getCause().getMessage(), conflict.getMessage());

    ResourceNotFoundException missing = assertThrows(ResourceNotFoundException.class, () -> store.getActiveBranchKey(b -> b.branchKeyIdentifier("missing")));
    assertEquals("No item found for corresponding branch key identifier.", missing.getMessage());
    assertNull(missing.getCause());
    assertThrows(ResourceNotFoundException.class, () -> store.versionKey(b -> b.branchKeyIdentifier("missing")));

    assertThrows(ValidationException.class, () -> store.createKey(b -> b.branchKeyIdentifier("").encryptionContext(EncryptionContext.of("k", "v"))));
    assertThrows(ValidationException.class, () -> store.createKey(b -> b.branchKeyIdentifier("id").encryptionContext(EncryptionContext.empty())));
    assertThrows(ValidationException.class, () -> store.versionKey(b -> b.branchKeyIdentifier("")));
    assertThrows(ValidationException.class, () -> builder(KmsConfiguration.discovery()).build().createKey());
    assertThrows(ValidationException.class, () -> builder(KmsConfiguration.discovery()).build().versionKey(b -> b.branchKeyIdentifier("taken")));
    String otherKey = aws.kms().createSymmetricKey(REGION);
    assertEquals(
      "Branch key's KMS Key ARN read from Dynamodb does not match Key Store's configured KMS Key ARN.",
      assertThrows(ValidationException.class, () -> builder(KmsConfiguration.kmsKeyArn(otherKey)).build().getActiveBranchKey(b -> b.branchKeyIdentifier("taken"))).getMessage()
    );

    putItem(item("corrupt", "branch:ACTIVE", "1"));
    assertEquals(
      "Item found is not a valid active branch key.",
      assertThrows(InvalidMaterialsException.class, () -> store.getActiveBranchKey(b -> b.branchKeyIdentifier("corrupt"))).getMessage()
    );
    Map<String, AttributeValue> alias = item("alias", "beacon:ACTIVE", null);
    alias.put("kms-arn", AttributeValue.builder().s("arn:aws:kms:us-west-2:111122223333:alias/a").build());
    putItem(alias);
    assertEquals(
      "The `kms-arn` field for the requested branch key identifier is corrupted.",
      assertThrows(InvalidMaterialsException.class, () -> store.getBeaconKey(b -> b.branchKeyIdentifier("alias"))).getMessage()
    );

    aws.kms().fail("Decrypt", null, ServiceError.accessDenied("denied"));
    AccessDeniedException denied = assertThrows(AccessDeniedException.class, () -> store.getActiveBranchKey(b -> b.branchKeyIdentifier("taken")));
    assertInstanceOf(software.amazon.awssdk.services.kms.model.KmsException.class, denied.getCause());
    assertFalse(denied.isRetryable());
    aws.kms().clearFailures();
    aws.kms().fail("Decrypt", null, ServiceError.throttling("slow"));
    ThrottlingException throttled = assertThrows(ThrottlingException.class, () -> store.getActiveBranchKey(b -> b.branchKeyIdentifier("taken")));
    assertTrue(throttled.isRetryable());
    aws.kms().clearFailures();
    aws.kms().fail("Decrypt", null, ServiceError.of("InvalidCiphertextException", "bad"));
    ServiceException service = assertThrows(ServiceException.class, () -> store.getActiveBranchKey(b -> b.branchKeyIdentifier("taken")));
    assertInstanceOf(software.amazon.awssdk.services.kms.model.InvalidCiphertextException.class, service.getCause());
    aws.kms().clearFailures();
    String unknownKey = "arn:aws:kms:us-west-2:111122223333:key/00000000-0000-4000-8000-999999999999";
    ResourceNotFoundException notFound = assertThrows(ResourceNotFoundException.class, () -> builder(KmsConfiguration.kmsKeyArn(unknownKey)).build().createKey());
    assertInstanceOf(software.amazon.awssdk.services.kms.model.NotFoundException.class, notFound.getCause());

    aws.dynamoDb().fail("GetItem", ServiceError.of("com.amazonaws.dynamodb.v20120810#ProvisionedThroughputExceededException", "busy"));
    assertThrows(ThrottlingException.class, () -> store.getBeaconKey(b -> b.branchKeyIdentifier("taken")));
    aws.dynamoDb().clearFailures();

    // A request that never reaches an endpoint.
    FakeAws stopped = FakeAws.start();
    java.net.URI endpoint = stopped.endpoint("native");
    stopped.close();
    try (
      KmsClient unreachable = KmsClient.builder()
        .region(software.amazon.awssdk.regions.Region.of(REGION))
        .endpointOverride(endpoint)
        .credentialsProvider(
          software.amazon.awssdk.auth.credentials.StaticCredentialsProvider.create(
            software.amazon.awssdk.auth.credentials.AwsBasicCredentials.create("AKIAFAKEAWS000000000", "fake")
          )
        )
        .overrideConfiguration(o -> o.retryStrategy(software.amazon.awssdk.awscore.retry.AwsRetryStrategy.doNotRetry()))
        .build()
    ) {
      MaterialProvidersException dispatch = assertThrows(
        DispatchException.class,
        () -> builder(KmsConfiguration.kmsKeyArn(kmsKey)).kmsClient(unreachable).build().getActiveBranchKey(b -> b.branchKeyIdentifier("taken")).branchKeyMaterials()
      );
      assertInstanceOf(SdkClientException.class, dispatch.getCause());
      assertTrue(dispatch.isRetryable());
    }
  }

  @Test
  void nullArgumentsAndMissingMembers() {
    DynamoDbKeyStore store = store();
    assertThrows(NullPointerException.class, () -> store.createKey((CreateKeyRequest) null));
    assertThrows(NullPointerException.class, () -> store.versionKey((VersionKeyRequest) null));
    assertThrows(NullPointerException.class, () -> store.getActiveBranchKey((GetActiveBranchKeyRequest) null));
    assertThrows(NullPointerException.class, () -> store.getBranchKeyVersion((GetBranchKeyVersionRequest) null));
    assertThrows(NullPointerException.class, () -> store.getBeaconKey((GetBeaconKeyRequest) null));
    assertThrows(NullPointerException.class, () -> store.createKeyStore((CreateKeyStoreRequest) null));
    assertThrows(NullPointerException.class, () -> store.getKeyStoreInfo((GetKeyStoreInfoRequest) null));
    String missing = "Missing value for required field `branchKeyIdentifier`";
    assertEquals(missing, assertThrows(ValidationException.class, () -> VersionKeyRequest.builder().branchKeyIdentifier(null).build()).getMessage());
    assertEquals(missing, assertThrows(ValidationException.class, () -> GetActiveBranchKeyRequest.builder().branchKeyIdentifier(null).build()).getMessage());
    assertEquals(missing, assertThrows(ValidationException.class, () -> GetBranchKeyVersionRequest.builder().branchKeyIdentifier(null).branchKeyVersion("v").build()).getMessage());
    assertEquals(missing, assertThrows(ValidationException.class, () -> GetBeaconKeyRequest.builder().branchKeyIdentifier(null).build()).getMessage());
    assertEquals(
      "Missing value for required field `branchKeyVersion`",
      assertThrows(ValidationException.class, () -> GetBranchKeyVersionRequest.builder().branchKeyIdentifier("id").branchKeyVersion(null).build()).getMessage()
    );
    // CreateKey's members are optional, but an id needs a non-empty encryption context, as in the Dafny model.
    assertEquals(
      "Custom branch key identifier requires custom encryption context.",
      assertThrows(ValidationException.class, () -> store.createKey(b -> b.branchKeyIdentifier("id"))).getMessage()
    );
  }

  @Test
  void consumerAndNoArgumentOverloadsBuildTheRequest() {
    DynamoDbKeyStore store = store();
    String id = store.createKey(b -> b.branchKeyIdentifier("consumer").encryptionContext(EncryptionContext.of("k", "v"))).branchKeyIdentifier();
    assertEquals("consumer", id);
    BranchKeyMaterials active = store.getActiveBranchKey(b -> b.branchKeyIdentifier(id)).branchKeyMaterials();
    assertEquals(EncryptionContext.of("k", "v"), active.encryptionContext());
    assertEquals(active, store.getBranchKeyVersion(b -> b.branchKeyIdentifier(id).branchKeyVersion(active.branchKeyVersion())).branchKeyMaterials());
    store.versionKey(b -> b.branchKeyIdentifier(id));
    assertNotEquals(active.branchKeyVersion(), store.getActiveBranchKey(GetActiveBranchKeyRequest.builder().branchKeyIdentifier(id).build()).branchKeyMaterials().branchKeyVersion());
    assertEquals(id, store.getBeaconKey(b -> b.branchKeyIdentifier(id)).beaconKeyMaterials().beaconKeyIdentifier());
    assertEquals(store.createKeyStore().tableArn(), store.createKeyStore(b -> {}).tableArn());
    assertSame(store.getKeyStoreInfo(), store.getKeyStoreInfo(b -> {}));
    assertSame(store.getKeyStoreInfo(), store.getKeyStoreInfo(GetKeyStoreInfoRequest.builder().build()));
    assertThrows(NullPointerException.class, () -> store.createKey((java.util.function.Consumer<CreateKeyRequest.Builder>) null));
  }

  private void putItem(Map<String, AttributeValue> item) {
    ddb.putItem(r -> r.tableName(TABLE).item(item));
  }

  // A key store item, without "version" when version is null; enc is not a valid KMS ciphertext.
  private Map<String, AttributeValue> item(String id, String type, String version) {
    Map<String, AttributeValue> item = new HashMap<>();
    item.put("branch-key-id", AttributeValue.builder().s(id).build());
    item.put("type", AttributeValue.builder().s(type).build());
    if (version != null) {
      item.put("version", AttributeValue.builder().s(version).build());
    }
    item.put("create-time", AttributeValue.builder().s("2024-01-01T00:00:00.000000Z").build());
    item.put("hierarchy-version", AttributeValue.builder().n("1").build());
    item.put("kms-arn", AttributeValue.builder().s(kmsKey).build());
    item.put("enc", AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[] { 1 })).build());
    return item;
  }

  private static String repeat(char c, int count) {
    char[] chars = new char[count];
    Arrays.fill(chars, c);
    return new String(chars);
  }
}
