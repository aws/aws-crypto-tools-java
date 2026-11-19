// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.config;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.discovery;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.keyArn;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.mrDiscovery;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.mrKeyArn;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.keystore.DynamoDbKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.internal.UserAgent;
import software.amazon.cryptography.oldapi.keystore.KeyStore;
import software.amazon.cryptography.oldapi.keystore.model.CreateKeyInput;
import software.amazon.cryptography.oldapi.keystore.model.CreateKeyStoreInput;
import software.amazon.cryptography.oldapi.keystore.model.GetActiveBranchKeyInput;
import software.amazon.cryptography.oldapi.keystore.model.KMSConfiguration;
import software.amazon.cryptography.oldapi.keystore.model.KeyStoreConfig;

/**
 * Stores that create their own clients: the Region they pick, and closing them.
 * The SDK's {@code aws.endpointUrl} system property points those clients at the fake endpoint.
 */
class KeyStoreDefaultClientsTest {

  private static final String KEY_REGION = "eu-west-1";
  private static final String DEFAULT_REGION = "ap-south-1";
  private static final String[] PROPERTIES = {
    "aws.endpointUrl",
    "aws.region",
    "aws.accessKeyId",
    "aws.secretAccessKey",
    "aws.configFile",
    "aws.disableEc2Metadata",
  };

  private final KeyStoreHarness harness = KeyStoreHarness.paired();
  private final Map<String, String> saved = new HashMap<>();

  KeyStoreDefaultClientsTest() {
    for (String property : PROPERTIES) {
      saved.put(property, System.getProperty(property));
    }
    System.setProperty("aws.accessKeyId", "AKIAFAKEAWS000000000");
    System.setProperty("aws.secretAccessKey", "fake-secret-access-key");
    System.setProperty("aws.region", DEFAULT_REGION);
  }

  @AfterEach
  void close() {
    for (String property : PROPERTIES) {
      if (saved.get(property) == null) {
        System.clearProperty(property);
      } else {
        System.setProperty(property, saved.get(property));
      }
    }
    harness.close();
  }

  //= spec/framework/branch-key-store.md#kms-client
  //= type=test
  //# If the AWS KMS Configuration is KMS Key ARN or KMS MRKey ARN,
  //# and no KMS Client is provided,
  //# a new KMS Client MUST be created
  //# with the region of the supplied KMS ARN.

  //= spec/framework/branch-key-store.md#dynamodb-client
  //= type=test
  //# If the AWS KMS Configuration is KMS Key ARN or KMS MRKey ARN,
  //# and no DynamoDb Client is provided,
  //# a new DynamoDb Client MUST be created
  //# with the region of the supplied KMS ARN.
  @Test
  void keyArnConfigurationsUseTheKeysRegion() {
    String key = harness.symmetricKey(KEY_REGION);
    List<String> mrk = harness.multiRegionKey(KEY_REGION, DEFAULT_REGION);
    run(keyArn(key), true);
    harness.clearRequests();
    run(mrKeyArn(mrk.get(0)), true);
  }

  //= spec/framework/branch-key-store.md#kms-client
  //= type=test
  //# If the AWS KMS Configuration is MRDiscovery,
  //# and no KMS Client is provided,
  //# a new KMS Client MUST be created
  //# with the region configured in the MRDiscovery.

  //= spec/framework/branch-key-store.md#dynamodb-client
  //= type=test
  //# If the AWS KMS Configuration is MRDiscovery,
  //# and no DynamoDb Client is provided,
  //# a new DynamoDb Client MUST be created
  //# with the region configured in the MRDiscovery.
  @Test
  void mrDiscoveryUsesItsRegion() {
    run(mrDiscovery(KEY_REGION), false);
  }

  //= spec/framework/branch-key-store.md#kms-client
  //= type=test
  //# If the AWS KMS Configuration is Discovery,
  //# and no KMS Client is provided,
  //# a new KMS Client MUST be created
  //# with the default configuration.

  //= spec/framework/branch-key-store.md#dynamodb-client
  //= type=test
  //# If the AWS KMS Configuration is Discovery,
  //# and no DynamoDb Client is provided,
  //# a new DynamoDb Client MUST be created
  //# with the default configuration.
  @Test
  void discoveryUsesTheDefaultRegion() {
    run(discovery(), false);
  }

  // Index.dfy reports the client it cannot create; the KMS client is created first.
  @Test
  void discoveryWithoutADefaultRegion() {
    Assumptions.assumeTrue(System.getenv("AWS_REGION") == null && System.getenv("AWS_DEFAULT_REGION") == null, "needs no Region in the environment");
    System.clearProperty("aws.region");
    System.setProperty("aws.configFile", "/nonexistent/aws-config");
    System.setProperty("aws.disableEc2Metadata", "true");
    KmsClient kms = harness.kms(KEY_REGION);
    for (KeyStoreConfig config : java.util.Arrays.asList(
      config(discovery(), null, null).build(),
      config(discovery(), kms, null).build(),
      config(discovery(), null, harness.ddb(KEY_REGION)).build()
    )) {
      KeyStoreHarness.Stores stores = KeyStoreHarness.stores(config);
      assertTrue(stores.nativeBuild.contains("Unable to load region"), stores.nativeBuild);
    }
  }

  @Test
  void closeClosesOnlyTheClientsTheStoreCreated() {
    String key = harness.symmetricKey(KEY_REGION);
    System.setProperty("aws.endpointUrl", harness.nativeAws.endpoint(ReferenceAws.NATIVE).toString());
    DynamoDbKeyStore owning = DynamoDbKeyStore.builder()
      .ddbTableName(KeyStoreHarness.TABLE)
      .logicalKeyStoreName(KeyStoreHarness.LOGICAL_NAME)
      .kmsConfiguration(KmsConfiguration.kmsKeyArn(key))
      .build();
    owning.createKeyStore();
    String id = owning.createKey().branchKeyIdentifier();
    assertNotNull(owning.getActiveBranchKey(b -> b.branchKeyIdentifier(id)).branchKeyMaterials());
    owning.close();
    assertThrows(IllegalStateException.class, () -> owning.getActiveBranchKey(b -> b.branchKeyIdentifier(id)));
    assertThrows(IllegalStateException.class, () -> owning.createKey());

    KmsClient kms = harness.nativeAws.kmsClient(ReferenceAws.NATIVE, KEY_REGION);
    DynamoDbClient ddb = harness.nativeAws.dynamoDbClient(ReferenceAws.NATIVE, KEY_REGION);
    DynamoDbKeyStore borrowing = DynamoDbKeyStore.builder()
      .ddbTableName(KeyStoreHarness.TABLE)
      .logicalKeyStoreName(KeyStoreHarness.LOGICAL_NAME)
      .kmsConfiguration(KmsConfiguration.kmsKeyArn(key))
      .kmsClient(kms)
      .ddbClient(ddb)
      .build();
    borrowing.close();
    assertNotNull(borrowing.getActiveBranchKey(b -> b.branchKeyIdentifier(id)).branchKeyMaterials());
    // A store with only one client passed in closes the other.
    DynamoDbKeyStore half = DynamoDbKeyStore.builder()
      .ddbTableName(KeyStoreHarness.TABLE)
      .logicalKeyStoreName(KeyStoreHarness.LOGICAL_NAME)
      .kmsConfiguration(KmsConfiguration.kmsKeyArn(key))
      .kmsClient(kms)
      .build();
    half.close();
    assertThrows(IllegalStateException.class, () -> half.getActiveBranchKey(b -> b.branchKeyIdentifier(id)));
  }

  // Builds each side's store without clients, aimed at its own endpoint, and runs the same operations on both.
  private void run(KMSConfiguration configuration, boolean createsKeys) {
    KeyStoreConfig config = config(configuration, null, null).build();
    System.setProperty("aws.endpointUrl", harness.nativeAws.endpoint(ReferenceAws.NATIVE).toString());
    KeyStore nativeStore = KeyStoreHarness.nativeStore(config);
    System.setProperty("aws.endpointUrl", harness.referenceAws.endpoint(ReferenceAws.REFERENCE).toString());
    Object referenceStore = KeyStoreHarness.referenceStore(config);
    System.clearProperty("aws.endpointUrl");

    same(nativeStore, referenceStore, "CreateKeyStore", CreateKeyStoreInput.builder().build());
    if (createsKeys) {
      same(nativeStore, referenceStore, "CreateKey", CreateKeyInput.builder().build());
    }
    same(nativeStore, referenceStore, "GetActiveBranchKey", GetActiveBranchKeyInput.builder().branchKeyIdentifier("missing").build());
    harness.assertSameRequests();
    for (FakeAws aws : harness.endpoints()) {
      assertFalse(aws.requests().isEmpty());
    }
    // Store-created KMS clients carry the library's user-agent suffix (R7), as the reference's carry its own; DynamoDB's do not.
    for (String userAgent : harness.nativeAws.userAgents()) {
      assertEquals(userAgent.startsWith("kms: "), userAgent.contains(UserAgent.SUFFIX), userAgent);
    }
    for (String userAgent : harness.referenceAws.userAgents()) {
      assertEquals(userAgent.startsWith("kms: "), userAgent.contains("AwsCryptographicMPL/Java/"), userAgent);
    }
  }

  // A blank Region cannot make a client; Dafny reported it as a client creation failure, not a raw exception.
  @Test
  void aBlankRegionFailsAsAClientCreationFailure() {
    for (KeyStoreConfig config : java.util.Arrays.asList(
      config(mrDiscovery(" "), null, null).build(),
      config(keyArn("arn:aws:kms: :111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"), null, null).build()
    )) {
      KeyStoreHarness.Stores stores = KeyStoreHarness.stores(config);
      assertEquals(stores.referenceBuild, stores.nativeBuild);
    }
  }

  // A store given only a DynamoDB client creates, owns, and closes its KMS client.
  @Test
  void closeClosesACreatedKmsClient() {
    String key = harness.symmetricKey(KEY_REGION);
    System.setProperty("aws.endpointUrl", harness.nativeAws.endpoint(ReferenceAws.NATIVE).toString());
    DynamoDbKeyStore setup = DynamoDbKeyStore.builder()
      .ddbTableName(KeyStoreHarness.TABLE)
      .logicalKeyStoreName(KeyStoreHarness.LOGICAL_NAME)
      .kmsConfiguration(KmsConfiguration.kmsKeyArn(key))
      .build();
    setup.createKeyStore();
    String id = setup.createKey().branchKeyIdentifier();
    setup.close();
    DynamoDbKeyStore half = DynamoDbKeyStore.builder()
      .ddbTableName(KeyStoreHarness.TABLE)
      .logicalKeyStoreName(KeyStoreHarness.LOGICAL_NAME)
      .kmsConfiguration(KmsConfiguration.kmsKeyArn(key))
      .ddbClient(harness.nativeAws.dynamoDbClient(ReferenceAws.NATIVE, KEY_REGION))
      .build();
    assertNotNull(half.getActiveBranchKey(b -> b.branchKeyIdentifier(id)).branchKeyMaterials());
    half.close();
    assertThrows(IllegalStateException.class, () -> half.getActiveBranchKey(b -> b.branchKeyIdentifier(id)));
  }

  private static void same(KeyStore nativeStore, Object referenceStore, String operation, Object input) {
    assertEquals(
      KeyStoreHarness.outcome(() -> ReferenceMpl.call(referenceStore, operation, input)),
      KeyStoreHarness.outcome(() -> KeyStoreHarness.nativeCall(nativeStore, operation, input)),
      operation
    );
  }
}
