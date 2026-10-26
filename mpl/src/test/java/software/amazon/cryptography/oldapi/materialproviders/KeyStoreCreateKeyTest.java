// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.EAST;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.LOGICAL_NAME;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.WEST;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.config;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.discovery;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.keyArn;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.mrDiscovery;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.mrKeyArn;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.sdkBytes;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.with;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.fakeaws.RecordedRequest;
import software.amazon.cryptography.materialproviders.fakeaws.ServiceError;
import software.amazon.cryptography.oldapi.keystore.model.CreateKeyInput;
import software.amazon.cryptography.oldapi.keystore.model.KMSConfiguration;
import software.amazon.cryptography.oldapi.keystore.model.KeyStoreConfig;

// CreateKey, native (through the adapter) against the reference, each on its own identically seeded endpoint.
class KeyStoreCreateKeyTest {

  private final KeyStoreHarness harness = KeyStoreHarness.paired();
  private final String kmsKey = harness.symmetricKey(WEST);

  @AfterEach
  void close() {
    harness.close();
  }

  //= spec/framework/branch-key-store.md#createkey
  //= type=test
  //# If no branch key id is provided,
  //# then this operation MUST create a [version 4 UUID](https://www.ietf.org/rfc/rfc4122.txt)
  //# to be used as the branch key id.

  //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
  //= type=test
  //# This guid MUST be [version 4 UUID](https://www.ietf.org/rfc/rfc4122.txt)

  //= spec/framework/branch-key-store.md#createkey
  //= type=test
  //# If an optional branch key id is provided
  //# and no encryption context is provided this operation MUST fail.

  //= spec/framework/branch-key-store.md#writing-branch-key-and-beacon-key-to-keystore
  //= type=test
  //# - Every key-value pair of the custom [encryption context](./structures.md#encryption-context-3) that is associated with the branch key
  //# MUST be added with an Attribute Name of `aws-crypto-ec:` + the Key and Attribute Value (S) of the value.
  @Test
  void inputs() {
    harness.createTable(WEST);
    List<CreateKeyInput> inputs = new ArrayList<>();
    inputs.add(CreateKeyInput.builder().build());
    inputs.add(CreateKeyInput.builder().encryptionContext(Collections.emptyMap()).build());
    inputs.add(CreateKeyInput.builder().encryptionContext(context("tenant", "a")).build());
    inputs.add(CreateKeyInput.builder().branchKeyIdentifier("custom-id").encryptionContext(context("tenant", "a", "k2", "v2")).build());
    inputs.add(CreateKeyInput.builder().branchKeyIdentifier("no-context").build());
    inputs.add(CreateKeyInput.builder().branchKeyIdentifier("empty-context").encryptionContext(Collections.emptyMap()).build());
    inputs.add(CreateKeyInput.builder().branchKeyIdentifier("").encryptionContext(context("tenant", "a")).build());
    inputs.add(CreateKeyInput.builder().branchKeyIdentifier("").build());
    inputs.add(CreateKeyInput.builder().branchKeyIdentifier("\uD800lone").encryptionContext(context("k", "v")).build());
    inputs.add(CreateKeyInput.builder().encryptionContext(context("\uD800", "v")).build());
    inputs.add(CreateKeyInput.builder().encryptionContext(context("k", "\uDC00")).build());
    // From TestCreateKeysWithSpecialECKeys.dfy, plus characters outside the Basic Multilingual Plane.
    inputs.add(CreateKeyInput.builder().encryptionContext(context("", "encryption")).build());
    inputs.add(CreateKeyInput.builder().encryptionContext(context(" ", "encryption")).build());
    inputs.add(
      CreateKeyInput.builder()
        .encryptionContext(
          context(
            "\n", "newline", "\t", "tab", "\r", "carriage-return", "   ", "multiple-spaces",
            "NormalKey", "Value with\nspecial\rchars\t", "\u0007", "bell-unicode", "\u0001", "unicode",
            "\u00e9t\u00e9", "\uD83D\uDE00", "aws-crypto-ec:nested", "", "type", "branch:ACTIVE"
          )
        )
        .build()
    );
    // The prefixed key must be a valid attribute name: at most 65535 characters.
    inputs.add(CreateKeyInput.builder().encryptionContext(context(repeat('k', 65535 - 14), "v")).build());
    inputs.add(CreateKeyInput.builder().encryptionContext(context(repeat('k', 65535 - 13), "v")).build());
    inputs.add(CreateKeyInput.builder().encryptionContext(context("\uD83D\uDE00" + repeat('k', 65535 - 16), "v")).build());
    for (CreateKeyInput input : inputs) {
      createKey(config(keyArn(kmsKey), harness.kms(WEST), harness.ddb(WEST)).build(), input);
    }
  }

  //= spec/framework/branch-key-store.md#createkey
  //= type=test
  //# If the Keystore's KMS Configuration is `Discovery` or `MRDiscovery`,
  //# this operation MUST fail.
  @Test
  void configurations() {
    harness.createTable(WEST);
    List<String> mrk = harness.multiRegionKey(WEST, EAST);
    String unknown = "arn:aws:kms:us-west-2:111122223333:key/00000000-0000-4000-8000-999999999999";
    List<KMSConfiguration> configurations = Arrays.asList(
      discovery(),
      mrDiscovery(WEST),
      mrKeyArn(kmsKey),
      mrKeyArn(mrk.get(0)),
      keyArn(mrk.get(0)),
      // A replica in another Region than the client's: KMS does not resolve it.
      mrKeyArn(mrk.get(1)),
      keyArn(mrk.get(1)),
      keyArn(unknown)
    );
    for (KMSConfiguration configuration : configurations) {
      CreateKeyInput input = CreateKeyInput.builder().encryptionContext(context("tenant", "a")).build();
      createKey(config(configuration, harness.kms(WEST), harness.ddb(WEST)).build(), input);
      createKey(config(configuration, harness.kms(WEST), harness.ddb(WEST)).build(), CreateKeyInput.builder().build());
    }
    // The custom-id check comes before the configuration check, and the configuration check before the empty-id check.
    createKey(config(discovery(), harness.kms(WEST), harness.ddb(WEST)).build(), CreateKeyInput.builder().branchKeyIdentifier("x").build());
    createKey(
      config(discovery(), harness.kms(WEST), harness.ddb(WEST)).build(),
      CreateKeyInput.builder().branchKeyIdentifier("").encryptionContext(context("k", "v")).build()
    );
  }

  @Test
  void anExistingIdConflicts() {
    harness.createTable(WEST);
    KeyStoreConfig config = config(keyArn(kmsKey), harness.kms(WEST), harness.ddb(WEST)).build();
    CreateKeyInput input = CreateKeyInput.builder().branchKeyIdentifier("taken").encryptionContext(context("k", "v")).build();
    createKey(config, input);
    String second = createKey(config, input);
    assertTrue(second.startsWith("throws software.amazon.awssdk.services.dynamodb.model.TransactionCanceledException"), second);
  }

  @Test
  void aMissingTableFailsTheWrite() {
    createKey(config(keyArn(kmsKey), harness.kms(WEST), harness.ddb(WEST)).build(), CreateKeyInput.builder().build());
  }

  @Test
  void serviceFailuresAtEachCall() {
    harness.createTable(WEST);
    // GenerateDataKeyWithoutPlaintext is called twice: the first version, then the beacon key.
    failNth("GenerateDataKeyWithoutPlaintext", 1, ServiceError.accessDenied("no GenerateDataKeyWithoutPlaintext"));
    failNth("GenerateDataKeyWithoutPlaintext", 2, ServiceError.of("KMSInternalException", "beacon failed"));
    failNth("ReEncrypt", 1, ServiceError.throttling("slow down"));
    failNth("ReEncrypt", 1, ServiceError.of("DisabledException", "disabled"));
    for (FakeAws aws : harness.endpoints()) {
      aws.dynamoDb().fail("TransactWriteItems", ServiceError.of("com.amazonaws.dynamodb.v20120810#ProvisionedThroughputExceededException", "busy"));
    }
    createKey(config(keyArn(kmsKey), harness.kms(WEST), harness.ddb(WEST)).build(), CreateKeyInput.builder().build());
  }

  // KMS answers that the fake cannot produce: each response check of KMSKeystoreOperations.dfy.
  @Test
  void unexpectedKmsResponses() {
    harness.createTable(WEST);
    for (int call = 1; call <= 2; call++) {
      tamperNth("generateDataKeyWithoutPlaintext", call, response -> with(response, "keyId", null));
      tamperNth("generateDataKeyWithoutPlaintext", call, response -> with(response, "ciphertextBlob", null));
      tamperNth("generateDataKeyWithoutPlaintext", call, response -> with(response, "ciphertextBlob", sdkBytes(response, new byte[0])));
      tamperNth("generateDataKeyWithoutPlaintext", call, response -> with(response, "ciphertextBlob", sdkBytes(response, new byte[6145])));
      tamperNth("generateDataKeyWithoutPlaintext", call, response -> with(response, "keyId", "some-other-key"));
    }
    tamperNth("generateDataKeyWithoutPlaintext", 1, response -> with(response, "ciphertextBlob", sdkBytes(response, new byte[6144])));
    tamperNth("generateDataKeyWithoutPlaintext", 1, response -> with(response, "ciphertextBlob", sdkBytes(response, new byte[1])));
    tamperNth("reEncrypt", 1, response -> with(response, "keyId", null));
    tamperNth("reEncrypt", 1, response -> with(response, "sourceKeyId", null));
    tamperNth("reEncrypt", 1, response -> with(response, "keyId", kmsKey + "x"));
    tamperNth("reEncrypt", 1, response -> with(response, "sourceKeyId", kmsKey + "x"));
    tamperNth("reEncrypt", 1, response -> with(response, "ciphertextBlob", null));
    tamperNth("reEncrypt", 1, response -> with(response, "ciphertextBlob", sdkBytes(response, new byte[0])));
    tamperNth("reEncrypt", 1, response -> with(response, "ciphertextBlob", sdkBytes(response, new byte[6145])));
    tamperNth("reEncrypt", 1, response -> with(response, "ciphertextBlob", sdkBytes(response, new byte[6144])));
  }

  // Both stores create a key; then each reads the other's, and both read the same items alike.
  @Test
  void eachSideReadsKeysTheOtherCreated() {
    try (KeyStoreHarness shared = KeyStoreHarness.shared()) {
      String key = shared.symmetricKey(WEST);
      shared.createTable(WEST);
      KeyStoreHarness.Stores stores = KeyStoreHarness.stores(config(keyArn(key), shared.kms(WEST), shared.ddb(WEST)).build());
      Object nativeCreated = KeyStoreHarness.nativeCall(
        stores.nativeStore,
        "CreateKey",
        CreateKeyInput.builder().branchKeyIdentifier("by-native").encryptionContext(context("made", "native", "", "empty")).build()
      );
      Object referenceCreated = ReferenceMpl.call(
        stores.referenceStore,
        "CreateKey",
        CreateKeyInput.builder().encryptionContext(context("made", "reference", "\uD83D\uDE00", "\n")).build()
      );
      String referenceId = (String) KeyStoreHarness.get(referenceCreated, "branchKeyIdentifier");
      assertEquals("by-native", KeyStoreHarness.get(nativeCreated, "branchKeyIdentifier"));
      for (String id : Arrays.asList("by-native", referenceId)) {
        String active = stores.same("GetActiveBranchKey", software.amazon.cryptography.oldapi.keystore.model.GetActiveBranchKeyInput.builder().branchKeyIdentifier(id).build());
        String version = activeVersion(shared, id);
        String byVersion = stores.same(
          "GetBranchKeyVersion",
          software.amazon.cryptography.oldapi.keystore.model.GetBranchKeyVersionInput.builder().branchKeyIdentifier(id).branchKeyVersion(version).build()
        );
        assertEquals(materials(active), materials(byVersion));
        String beacon = stores.same("GetBeaconKey", software.amazon.cryptography.oldapi.keystore.model.GetBeaconKeyInput.builder().branchKeyIdentifier(id).build());
        assertNotEquals(key(active), key(beacon));
      }
    }
  }

  //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
  //= type=test
  //# - `timestamp`: a timestamp for the current time.
  //# This timestamp MUST be in ISO8601 format in UTC, to microsecond precision (e.g. “YYYY-MM-DDTHH:mm:ss.ssssssZ“)

  //= spec/framework/branch-key-store.md#logical-keystore-name
  //= type=test
  //# The logical keystore name MUST be bound to every created key.

  //= spec/framework/branch-key-store.md#active-encryption-context
  //= type=test
  //# The ACTIVE encryption context value of the `type` attribute MUST equal to `"branch:ACTIVE"`.

  //= spec/framework/branch-key-store.md#beacon-key-encryption-context
  //= type=test
  //# The Beacon key encryption context value of the `type` attribute MUST equal to `"beacon:ACTIVE"`.

  //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
  //= type=test
  //# - `SourceEncryptionContext` MUST be the [DECRYPT_ONLY encryption context for branch keys](#decrypt_only-encryption-context).
  // The items the native store writes, beyond what the masked request comparison shows.
  @Test
  void nativeItemsShareOneVersionAndTimestamp() {
    harness.createTable(WEST);
    KeyStoreHarness.Stores stores = KeyStoreHarness.stores(config(keyArn(kmsKey), harness.kms(WEST), harness.ddb(WEST)).build());
    harness.clearRequests();
    KeyStoreHarness.nativeCall(stores.nativeStore, "CreateKey", CreateKeyInput.builder().encryptionContext(context("tenant", "a")).build());
    List<RecordedRequest> requests = harness.nativeAws.requests(ReferenceAws.NATIVE);
    JsonNode decryptOnly = requests.get(0).body().get("EncryptionContext");
    JsonNode reEncrypt = requests.get(1).body();
    JsonNode beacon = requests.get(2).body().get("EncryptionContext");
    JsonNode items = requests.get(3).body().get("TransactItems");

    String id = decryptOnly.get("branch-key-id").asText();
    String type = decryptOnly.get("type").asText();
    assertTrue(type.matches("branch:version:[0-9a-f-]{36}"), type);
    assertNotEquals(id, type.substring("branch:version:".length()));
    String createTime = decryptOnly.get("create-time").asText();
    assertTrue(createTime.matches("\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\d\\.0\\d{5}Z"), createTime);
    // UTC: within a minute of now, read back with the same pattern.
    java.text.SimpleDateFormat format = new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'");
    format.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
    long created = format.parse(createTime, new java.text.ParsePosition(0)).getTime();
    assertTrue(Math.abs(System.currentTimeMillis() - created) < 60_000, createTime);
    assertEquals(decryptOnly, reEncrypt.get("SourceEncryptionContext"));
    JsonNode active = reEncrypt.get("DestinationEncryptionContext");
    assertEquals(type, active.get("version").asText());
    assertEquals("branch:ACTIVE", active.get("type").asText());
    assertEquals("beacon:ACTIVE", beacon.get("type").asText());
    assertEquals(LOGICAL_NAME, decryptOnly.get("tablename").asText());
    for (String name : Arrays.asList("branch-key-id", "create-time", "kms-arn", "hierarchy-version", "aws-crypto-ec:tenant", "tablename")) {
      assertEquals(decryptOnly.get(name), active.get(name), name);
      assertEquals(decryptOnly.get(name), beacon.get(name), name);
    }
    assertEquals(fields(decryptOnly).size() + 1, fields(active).size());
    assertEquals(fields(decryptOnly).size(), fields(beacon).size());

    // Each item holds its context, minus tablename, with hierarchy-version a number, plus the wrapped key.
    JsonNode[] contexts = { decryptOnly, active, beacon };
    for (int i = 0; i < 3; i++) {
      JsonNode item = items.get(i).get("Put").get("Item");
      Map<String, String> expected = new HashMap<>();
      for (String name : fields(contexts[i])) {
        if (!name.equals("tablename")) {
          expected.put(name, (name.equals("hierarchy-version") ? "N " : "S ") + contexts[i].get(name).asText());
        }
      }
      Map<String, String> actual = new HashMap<>();
      for (String name : fields(item)) {
        if (!name.equals("enc")) {
          String attributeType = item.get(name).fieldNames().next();
          actual.put(name, attributeType + " " + item.get(name).get(attributeType).asText());
        }
      }
      assertEquals(expected, actual);
      assertTrue(item.get("enc").has("B"));
    }
    assertEquals("1", decryptOnly.get("hierarchy-version").asText());
  }

  private static List<String> fields(JsonNode node) {
    List<String> names = new ArrayList<>();
    Iterator<String> it = node.fieldNames();
    while (it.hasNext()) {
      names.add(it.next());
    }
    return names;
  }

  private static String activeVersion(KeyStoreHarness shared, String id) {
    Map<String, AttributeValue> active = shared.item(WEST, id, "branch:ACTIVE");
    return active.get("version").s().substring("branch:version:".length());
  }

  private static String materials(String outcome) {
    return outcome.substring(outcome.indexOf("branchKeyMaterials="));
  }

  private static String key(String outcome) {
    int start = outcome.indexOf("0x");
    return outcome.substring(start, outcome.indexOf(',', start));
  }

  // Runs CreateKey with the {@code call}-th call of a KMS operation failing on both endpoints.
  private void failNth(String operation, int call, ServiceError error) {
    KmsClient kms = harness.kms(
      WEST,
      Character.toLowerCase(operation.charAt(0)) + operation.substring(1),
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
    createKey(config(keyArn(kmsKey), kms, harness.ddb(WEST)).build(), CreateKeyInput.builder().build());
  }

  private void tamperNth(String method, int call, java.util.function.Function<Object, Object> change) {
    KmsClient kms = harness.kms(WEST, method, (number, request, proceed) -> number == call ? change.apply(proceed.get()) : proceed.get());
    createKey(config(keyArn(kmsKey), kms, harness.ddb(WEST)).build(), CreateKeyInput.builder().build());
  }

  private String createKey(KeyStoreConfig config, CreateKeyInput input) {
    harness.clearRequests();
    KeyStoreHarness.Stores stores = KeyStoreHarness.stores(config);
    String outcome = stores.same("CreateKey", input);
    harness.assertSameRequests();
    return outcome;
  }

  static Map<String, String> context(String... keysAndValues) {
    Map<String, String> context = new HashMap<>();
    for (int i = 0; i < keysAndValues.length; i += 2) {
      context.put(keysAndValues[i], keysAndValues[i + 1]);
    }
    return context;
  }

  static String repeat(char c, int count) {
    char[] chars = new char[count];
    Arrays.fill(chars, c);
    return new String(chars);
  }
}
