// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreCreateKeyTest.context;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.EAST;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.WEST;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.config;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.discovery;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.keyArn;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.mrDiscovery;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.mrKeyArn;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.with;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.oldapi.keystore.model.CreateKeyInput;
import software.amazon.cryptography.oldapi.keystore.model.GetActiveBranchKeyInput;
import software.amazon.cryptography.oldapi.keystore.model.GetBeaconKeyInput;
import software.amazon.cryptography.oldapi.keystore.model.GetBranchKeyVersionInput;
import software.amazon.cryptography.oldapi.keystore.model.KMSConfiguration;
import software.amazon.cryptography.oldapi.keystore.model.VersionKeyInput;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.fakeaws.ServiceError;

// VersionKey, native (through the adapter) against the reference, each on its own identically seeded endpoint.
class KeyStoreVersionKeyTest {

  private static final String ID = "versioned";

  private final KeyStoreHarness harness = KeyStoreHarness.paired();
  private final String kmsKey = harness.symmetricKey(WEST);
  private final List<String> mrk = harness.multiRegionKey(WEST, EAST);

  KeyStoreVersionKeyTest() {
    harness.createTable(WEST);
  }

  @AfterEach
  void close() {
    harness.close();
  }

  //= spec/framework/branch-key-store.md#versionkey
  //= type=test
  //# - Every key-value pair of the custom [encryption context](./structures.md#encryption-context-3) that is associated with the branch key
  //# MUST be added with an Attribute Name of `aws-crypto-ec:` + the Key and Attribute Value (S) of the value.

  //= spec/framework/branch-key-store.md#custom-encryption-context
  //= type=test
  //# Across all versions of a Branch Key, the custom encryption context MUST be equal.
  @Test
  void versionsAndKeepsEarlierVersions() {
    KeyStoreHarness.Stores stores = create(keyArn(kmsKey));
    String[] first = activeVersions();
    versionKey(stores);
    String[] second = activeVersions();
    versionKey(stores);
    String[] third = activeVersions();
    assertEquals(3, Arrays.asList(first[0], second[0], third[0]).stream().distinct().count());
    assertVersions(stores, first, second, third);
  }

  //= spec/framework/branch-key-store.md#versionkey
  //= type=test
  //# The `kms-arn` stored in the DDB table MUST NOT change as a result of this operation,
  //# even if the KeyStore is configured with a `KMS MRKey ARN` that does not exactly match the stored ARN.

  //= spec/framework/branch-key-store.md#versionkey
  //= type=test
  //# The `kms-arn` field of DDB response item MUST be [compatible with](#aws-key-arn-compatibility)
  //# the configured `KMS ARN` in the [AWS KMS Configuration](#aws-kms-configuration) for this keystore.
  @Test
  void multiRegionKeyFromAnotherRegion() {
    // Created through the us-west-2 replica, versioned through the us-east-1 one; the table stays in us-west-2.
    create(mrKeyArn(mrk.get(0)));
    KeyStoreHarness.Stores east = KeyStoreHarness.pairedStores(config(mrKeyArn(mrk.get(1)), harness.kms(EAST), harness.ddb(WEST)).build());
    versionKey(east);
    String[] second = activeVersions();
    assertVersions(east, second);
    // Every replica reads it: through the configured ARN, or through MR-discovery in the client's Region.
    assertVersions(KeyStoreHarness.pairedStores(config(keyArn(mrk.get(0)), harness.kms(WEST), harness.ddb(WEST)).build()), second);
    assertVersions(KeyStoreHarness.pairedStores(config(mrDiscovery(EAST), harness.kms(EAST), harness.ddb(WEST)).build()), second);
    assertVersions(KeyStoreHarness.pairedStores(config(discovery(), harness.kms(WEST), harness.ddb(WEST)).build()), second);
    // A key ARN configuration for the other replica must match exactly, so it refuses the stored ARN.
    String exact = versionKey(KeyStoreHarness.pairedStores(config(keyArn(mrk.get(1)), harness.kms(EAST), harness.ddb(WEST)).build()), ID);
    assertTrue(exact.contains("does not match Key Store's configured KMS Key ARN"), exact);
  }

  //= spec/framework/branch-key-store.md#versionkey
  //= type=test
  //# If the Keystore's KMS Configuration is `Discovery` or `MRDiscovery`,
  //# this operation MUST immediately fail.
  @Test
  void configurationsAndInputs() {
    create(keyArn(kmsKey));
    for (KMSConfiguration configuration : Arrays.asList(discovery(), mrDiscovery(WEST))) {
      KeyStoreHarness.Stores stores = KeyStoreHarness.pairedStores(config(configuration, harness.kms(WEST), harness.ddb(WEST)).build());
      versionKey(stores, ID);
      versionKey(stores, "");
    }
    KeyStoreHarness.Stores stores = KeyStoreHarness.pairedStores(config(keyArn(kmsKey), harness.kms(WEST), harness.ddb(WEST)).build());
    versionKey(stores, "");
    versionKey(stores, "missing");
    // Another key ARN than the one the branch key names.
    String otherKey = harness.symmetricKey(WEST);
    versionKey(KeyStoreHarness.pairedStores(config(keyArn(otherKey), harness.kms(WEST), harness.ddb(WEST)).build()), ID);
    versionKey(KeyStoreHarness.pairedStores(config(mrKeyArn(otherKey), harness.kms(WEST), harness.ddb(WEST)).build()), ID);
  }

  //= spec/framework/branch-key-store.md#versionkey
  //= type=test
  //# If the item fails to authenticate this operation MUST fail.
  @Test
  void anotherLogicalNameFailsToAuthenticate() {
    create(keyArn(kmsKey));
    versionKey(KeyStoreHarness.pairedStores(config(keyArn(kmsKey), harness.kms(WEST), harness.ddb(WEST)).logicalKeyStoreName("other").build()), ID);
  }

  @Test
  void serviceFailuresAtEachCall() {
    create(keyArn(kmsKey));
    failNth("reEncrypt", "ReEncrypt", 1, ServiceError.of("InvalidCiphertextException", "not authentic"));
    failNth("generateDataKeyWithoutPlaintext", "GenerateDataKeyWithoutPlaintext", 1, ServiceError.throttling("slow"));
    failNth("reEncrypt", "ReEncrypt", 2, ServiceError.accessDenied("no ReEncrypt"));
    for (FakeAws aws : harness.endpoints()) {
      aws.dynamoDb().fail("TransactWriteItems", ServiceError.of("com.amazonaws.dynamodb.v20120810#TransactionCanceledException", "cancelled"));
    }
    versionKey(KeyStoreHarness.pairedStores(config(keyArn(kmsKey), harness.kms(WEST), harness.ddb(WEST)).build()), ID);
    for (FakeAws aws : harness.endpoints()) {
      aws.dynamoDb().clearFailures();
      aws.dynamoDb().fail("GetItem", ServiceError.of("com.amazonaws.dynamodb.v20120810#ResourceNotFoundException", "no table"));
    }
    versionKey(KeyStoreHarness.pairedStores(config(keyArn(kmsKey), harness.kms(WEST), harness.ddb(WEST)).build()), ID);
  }

  @Test
  void unexpectedKmsResponses() {
    create(keyArn(kmsKey));
    List<Function<Object, Object>> changes = Arrays.asList(
      response -> with(response, "keyId", null),
      response -> with(response, "sourceKeyId", mrk.get(0)),
      response -> with(response, "ciphertextBlob", null)
    );
    for (int call = 1; call <= 2; call++) {
      for (Function<Object, Object> change : changes) {
        int target = call;
        KmsClient kms = harness.kms(WEST, "reEncrypt", (number, request, proceed) -> number == target ? change.apply(proceed.get()) : proceed.get());
        versionKey(KeyStoreHarness.pairedStores(config(keyArn(kmsKey), kms, harness.ddb(WEST)).build()), ID);
      }
    }
    KmsClient kms = harness.kms(WEST, "generateDataKeyWithoutPlaintext", (number, request, proceed) -> with(proceed.get(), "keyId", null));
    versionKey(KeyStoreHarness.pairedStores(config(keyArn(kmsKey), kms, harness.ddb(WEST)).build()), ID);
  }

  // VersionKey has no lock on the ACTIVE item: a concurrent VersionKey that writes first is overwritten.
  @Test
  void aConcurrentVersionKeyLosesSilently() {
    KeyStoreHarness.Stores inner = create(keyArn(kmsKey));
    String[] first = activeVersions();
    VersionKeyInput input = VersionKeyInput.builder().branchKeyIdentifier(ID).build();
    String[] innerVersions = new String[2];
    DynamoDbClient racing = harness.ddb(
      WEST,
      "transactWriteItems",
      (number, request, proceed) -> {
        // Just before the outer write, the other VersionKey on the same side runs to completion.
        if (request.getClass().getClassLoader() == TransactWriteItemsRequest.class.getClassLoader()) {
          KeyStoreHarness.nativeCall(inner.nativeStore, "VersionKey", input);
          innerVersions[0] = activeVersion(harness.nativeAws);
        } else {
          ReferenceMpl.call(inner.referenceStore, "VersionKey", input);
          innerVersions[1] = activeVersion(harness.referenceAws);
        }
        return proceed.get();
      }
    );
    KeyStoreHarness.Stores outer = KeyStoreHarness.pairedStores(config(keyArn(kmsKey), harness.kms(WEST), racing).build());
    harness.clearRequests();
    assertEquals("VersionKeyOutput{}", outer.same("VersionKey", input));
    harness.assertSameRequests();
    String[] last = activeVersions();
    assertNotEquals(innerVersions[0], last[0]);
    assertNotEquals(innerVersions[1], last[1]);
    // The concurrent version stays readable, but is no longer ACTIVE.
    assertVersions(outer, first, innerVersions, last);
  }

  private void failNth(String method, String operation, int call, ServiceError error) {
    KmsClient kms = harness.kms(
      WEST,
      method,
      (number, request, proceed) -> {
        if (number != call) {
          return proceed.get();
        }
        for (FakeAws endpoint : harness.endpoints()) {
          endpoint.kms().fail(operation, null, error);
        }
        try {
          return proceed.get();
        } finally {
          for (FakeAws endpoint : harness.endpoints()) {
            endpoint.kms().clearFailures();
          }
        }
      }
    );
    versionKey(KeyStoreHarness.pairedStores(config(keyArn(kmsKey), kms, harness.ddb(WEST)).build()), ID);
  }

  // Both sides create the branch key ID, each on its own endpoint, with a custom encryption context.
  private KeyStoreHarness.Stores create(KMSConfiguration configuration) {
    KeyStoreHarness.Stores stores = KeyStoreHarness.pairedStores(config(configuration, harness.kms(WEST), harness.ddb(WEST)).build());
    stores.same("CreateKey", CreateKeyInput.builder().branchKeyIdentifier(ID).encryptionContext(context("tenant", "a", "", "b")).build());
    return stores;
  }

  private void versionKey(KeyStoreHarness.Stores stores) {
    String outcome = versionKey(stores, ID);
    assertEquals("VersionKeyOutput{}", outcome);
  }

  private String versionKey(KeyStoreHarness.Stores stores, String id) {
    harness.clearRequests();
    String outcome = stores.same("VersionKey", VersionKeyInput.builder().branchKeyIdentifier(id).build());
    harness.assertSameRequests();
    return outcome;
  }

  // Each side reads its own versions alike, ACTIVE is the last one, and the beacon key and custom context are unchanged.
  private void assertVersions(KeyStoreHarness.Stores stores, String[]... versions) {
    String active = stores.same("GetActiveBranchKey", GetActiveBranchKeyInput.builder().branchKeyIdentifier(ID).build());
    String last = null;
    for (String[] version : versions) {
      last = stores.same("GetBranchKeyVersion", versionInput(version[0]), versionInput(version[1]));
      assertTrue(last.contains("encryptionContext={\"\"=\"b\", \"tenant\"=\"a\"}"), last);
    }
    assertEquals(active.substring(active.indexOf('{')), last.substring(last.indexOf('{')));
    String beacon = stores.same("GetBeaconKey", GetBeaconKeyInput.builder().branchKeyIdentifier(ID).build());
    assertTrue(beacon.startsWith("GetBeaconKeyOutput"), beacon);
  }

  private static GetBranchKeyVersionInput versionInput(String version) {
    return GetBranchKeyVersionInput.builder().branchKeyIdentifier(ID).branchKeyVersion(version).build();
  }

  // The ACTIVE version on the native endpoint and on the reference endpoint.
  private String[] activeVersions() {
    return new String[] { activeVersion(harness.nativeAws), activeVersion(harness.referenceAws) };
  }

  private static String activeVersion(FakeAws aws) {
    Map<String, AttributeValue> key = new java.util.HashMap<>();
    key.put("branch-key-id", AttributeValue.builder().s(ID).build());
    key.put("type", AttributeValue.builder().s("branch:ACTIVE").build());
    return aws
      .dynamoDbClient("setup", WEST)
      .getItem(r -> r.tableName(KeyStoreHarness.TABLE).key(key))
      .item()
      .get("version")
      .s()
      .substring("branch:version:".length());
  }
}
