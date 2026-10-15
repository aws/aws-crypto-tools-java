// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static software.amazon.cryptography.materialproviders.KeyStoreHarness.EAST;
import static software.amazon.cryptography.materialproviders.KeyStoreHarness.LOGICAL_NAME;
import static software.amazon.cryptography.materialproviders.KeyStoreHarness.WEST;
import static software.amazon.cryptography.materialproviders.KeyStoreHarness.config;
import static software.amazon.cryptography.materialproviders.KeyStoreHarness.discovery;
import static software.amazon.cryptography.materialproviders.KeyStoreHarness.keyArn;
import static software.amazon.cryptography.materialproviders.KeyStoreHarness.mrDiscovery;
import static software.amazon.cryptography.materialproviders.KeyStoreHarness.mrKeyArn;
import static software.amazon.cryptography.materialproviders.KeyStoreHarness.with;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.keystore.model.GetActiveBranchKeyInput;
import software.amazon.cryptography.keystore.model.GetBeaconKeyInput;
import software.amazon.cryptography.keystore.model.GetBranchKeyVersionInput;
import software.amazon.cryptography.keystore.model.KMSConfiguration;
import software.amazon.cryptography.keystore.model.VersionKeyInput;
import software.amazon.cryptography.materialproviders.fakeaws.ServiceError;

/**
 * GetActiveBranchKey, GetBranchKeyVersion, GetBeaconKey, and the read that starts VersionKey,
 * native (through the adapter) against the reference, both reading the same item.
 * The item comes from a DynamoDB client that answers GetItem with it, so it can break any rule of Structure.dfy.
 */
class KeyStoreGetKeysTest {

  private static final String ID = "branch-key";
  private static final String VERSION = "11111111-2222-4333-8444-555555555555";
  private static final String TIMESTAMP = "2024-01-02T03:04:05.000678Z";

  private enum Kind {
    ACTIVE,
    VERSION,
    BEACON,
  }

  private final KeyStoreHarness harness = KeyStoreHarness.shared();
  private final String kmsKey = harness.symmetricKey(WEST);
  private final String otherKey = harness.symmetricKey(WEST);
  private final String eastKey = harness.symmetricKey(EAST);
  private final List<String> mrk = harness.multiRegionKey(WEST, EAST);
  private final List<String> otherMrk = harness.multiRegionKey(WEST, EAST);
  private final KmsClient setupKms = harness.nativeAws.kmsClient("setup", WEST);
  // One set of clients for every read: the fake endpoint closes idle connections beyond a limit,
  // and a client per read would leave hundreds open.
  private final KmsClient kms = harness.kms(WEST);
  private final DynamoDbClient ddb = harness.ddb(WEST);
  private Map<String, AttributeValue> served;
  private final DynamoDbClient serving = harness.ddb(WEST, "getItem", (call, request, proceed) -> {
    Object response = proceed.get();
    return with(response, "item", served == null ? null : KeyStoreHarness.attributeMap(response, served));
  });

  KeyStoreGetKeysTest() {
    harness.createTable(WEST);
  }

  @AfterEach
  void close() {
    harness.close();
  }

  @Test
  void validItems() {
    for (Kind kind : Kind.values()) {
      read(keyArn(kmsKey), kind, sealed(base(kind, kmsKey), kmsKey));
    }
  }

  @Test
  void missingItems() {
    for (Kind kind : Kind.values()) {
      read(keyArn(kmsKey), kind, null);
      read(keyArn(kmsKey), kind, new HashMap<>());
    }
  }

  //= spec/framework/branch-key-store.md#getactivebranchkey
  //= type=test
  //# If the record does not contain the defined fields, this operation MUST fail.

  //= spec/framework/branch-key-store.md#getbranchkeyversion
  //= type=test
  //# If the record does not contain the defined fields, this operation MUST fail.

  //= spec/framework/branch-key-store.md#getbeaconkey
  //= type=test
  //# If the record does not contain the defined fields, this operation MUST fail.
  @Test
  void attributesMissingOrOfTheWrongType() {
    List<String> required = Arrays.asList("branch-key-id", "type", "create-time", "hierarchy-version", "kms-arn", "enc", "version");
    for (Kind kind : Kind.values()) {
      for (String name : required) {
        Map<String, AttributeValue> item = sealed(base(kind, kmsKey), kmsKey);
        item.remove(name);
        read(keyArn(kmsKey), kind, item);
        for (AttributeValue wrongType : Arrays.asList(n("1"), s("text"), b(new byte[] { 1 }), AttributeValue.builder().bool(true).build())) {
          Map<String, AttributeValue> changed = sealed(base(kind, kmsKey), kmsKey);
          changed.put(name, wrongType);
          read(keyArn(kmsKey), kind, changed);
        }
      }
    }
  }

  @Test
  void attributeValues() {
    for (Kind kind : Kind.values()) {
      List<Consumer<Map<String, AttributeValue>>> changes = Arrays.asList(
        item -> item.put("branch-key-id", s("")),
        item -> item.put("branch-key-id", s("another-branch-key")),
        item -> item.put("type", s("")),
        item -> item.put("type", s("branch:ACTIVE")),
        item -> item.put("type", s("beacon:ACTIVE")),
        item -> item.put("type", s("branch:version:")),
        item -> item.put("type", s("branch:version:x")),
        item -> item.put("type", s("branch:version")),
        item -> item.put("type", s("branch:versions:" + VERSION)),
        item -> item.put("type", s("Branch:ACTIVE")),
        item -> item.put("version", s("branch:version:" + VERSION)),
        item -> item.put("version", s("branch:version:")),
        item -> item.put("version", s("branch:version:x")),
        item -> item.put("version", s(VERSION)),
        item -> item.remove("version"),
        item -> item.put("tablename", s(LOGICAL_NAME)),
        item -> item.put("hierarchy-version", n("2")),
        item -> item.put("create-time", s("")),
        item -> item.put("extra", s("an unknown string attribute")),
        item -> item.put("aws-crypto-ec:", s("empty key")),
        item -> item.put("aws-crypto-ec:aws-crypto-ec:", s("double prefix")),
        item -> item.put("AWS-CRYPTO-EC:upper", s("not custom")),
        item -> item.put("x-aws-crypto-ec:inside", s("not custom")),
        item -> item.put("extra", n("1")),
        item -> item.put("extra", b(new byte[] { 1 })),
        item -> item.put("extra", AttributeValue.builder().bool(false).build()),
        item -> item.put("extra", AttributeValue.builder().nul(true).build()),
        item -> item.put("extra", AttributeValue.builder().ss("a", "b").build())
      );
      for (Consumer<Map<String, AttributeValue>> change : changes) {
        Map<String, AttributeValue> item = base(kind, kmsKey);
        change.accept(item);
        read(keyArn(kmsKey), kind, sealed(item, kmsKey));
      }
    }
  }

  //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
  //= type=test
  //# If the Keystore's [AWS KMS Configuration](#aws-kms-configuration) is `KMS Key ARN` or `KMS MRKey ARN`,
  //# the `kms-arn` field of the DDB response item MUST be
  //# [compatible with](#aws-key-arn-compatibility) the configured KMS Key in
  //# the [AWS KMS Configuration](#aws-kms-configuration) for this keystore,
  //# or the operation MUST fail.

  //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
  //= type=test
  //# If the Keystore's [AWS KMS Configuration](#aws-kms-configuration) is `Discovery` or `MRDiscovery`,
  //# the `kms-arn` field of DDB response item MUST NOT be an Alias
  //# or the operation MUST fail.

  //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
  //= type=test
  //# If the KMS Configuration is MRDiscovery, `KeyId` MUST be the `kms-arn` attribute value of the AWS DDB response item, with the region replaced by the configured region.
  @Test
  void storedKmsKeyArns() {
    List<String> arns = Arrays.asList(
      "",
      repeat('a', 2048),
      repeat('a', 2049),
      "arn:aws:kms:us-west-2:111122223333:alias/my-alias",
      "arn:aws:kms:us-west-2:111122223333:key/",
      "arn:aws:kms:us-west-2:111122223333:key/" + repeat('k', 2048 - 39),
      "arn:aws:kms:us-west-2:111122223333:key/" + repeat('k', 2049 - 39),
      "not-an-arn",
      kmsKey,
      otherKey,
      eastKey,
      mrk.get(0),
      mrk.get(1),
      otherMrk.get(1),
      // The us-east-1 replica's ARN changed in one part at a time.
      mrk.get(1).replace("111122223333", "444455556666"),
      mrk.get(1).replace("arn:aws:", "arn:aws-cn:"),
      mrk.get(1).replace(":key/", ":alias/"),
      "arn:aws:kms:us-east-1:111122223333:key/mrkabc",
      // A multi-Region key ARN that a longer Region would push past 2048 characters.
      "arn:aws:kms:us-west-2:111122223333:key/mrk-" + repeat('m', 2048 - 43)
    );
    List<KMSConfiguration> configurations = Arrays.asList(
      keyArn(kmsKey),
      mrKeyArn(kmsKey),
      keyArn(mrk.get(0)),
      mrKeyArn(mrk.get(0)),
      mrKeyArn(mrk.get(1)),
      mrKeyArn("arn:aws:kms:us-west-2:111122223333:key/mrkabc"),
      discovery(),
      mrDiscovery(WEST),
      mrDiscovery(EAST),
      mrDiscovery(repeat('r', 32))
    );
    for (KMSConfiguration configuration : configurations) {
      for (String arn : arns) {
        for (Kind kind : Kind.values()) {
          // Sealed under the key the item names where it exists, so a read that reaches KMS can succeed.
          String sealingKey = Arrays.asList(otherKey, eastKey, mrk.get(0), mrk.get(1)).contains(arn) ? arn : kmsKey;
          read(configuration, kind, sealed(base(kind, arn), sealingKey));
        }
      }
    }
  }

  //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
  //= type=test
  //# Every attribute except for `enc` on the AWS DDB response item
  //# MUST be authenticated in the decryption of `enc`
  @Test
  void wrappedKeys() {
    for (Kind kind : Kind.values()) {
      for (byte[] enc : Arrays.asList(new byte[0], new byte[1], new byte[6144], new byte[6145])) {
        Map<String, AttributeValue> item = base(kind, kmsKey);
        item.put("enc", b(enc));
        read(keyArn(kmsKey), kind, item);
      }
      // Not 32 bytes once decrypted.
      for (int length : new int[] { 16, 31, 33, 64 }) {
        read(keyArn(kmsKey), kind, sealed(base(kind, kmsKey), kmsKey, length));
      }
      // TestLyingBranchKey.dfy: the item names one key, another key wrapped it.
      read(keyArn(kmsKey), kind, sealed(base(kind, kmsKey), otherKey));
      // A context other than the item's: an attribute added after wrapping, or another logical name.
      Map<String, AttributeValue> item = sealed(base(kind, kmsKey), kmsKey);
      item.put("added", s("after wrapping"));
      read(keyArn(kmsKey), kind, item);
      read(keyArn(kmsKey), kind, sealed(base(kind, kmsKey), kmsKey, 32, "another-logical-name"));
    }
  }

  //= spec/framework/branch-key-store.md#getactivebranchkey
  //= type=test
  //# If the branch key fails to decrypt, GetActiveBranchKey MUST fail.

  //= spec/framework/branch-key-store.md#getbranchkeyversion
  //= type=test
  //# If the branch key fails to decrypt, this operation MUST fail.

  //= spec/framework/branch-key-store.md#getbeaconkey
  //= type=test
  //# If the beacon key fails to decrypt, this operation MUST fail.
  @Test
  void serviceFailures() {
    for (Kind kind : Kind.values()) {
      harness.nativeAws.kms().fail("Decrypt", null, ServiceError.accessDenied("no Decrypt"));
      read(keyArn(kmsKey), kind, sealed(base(kind, kmsKey), kmsKey));
      harness.nativeAws.kms().clearFailures();
      harness.nativeAws.kms().fail("Decrypt", kmsKey, ServiceError.of("KMSInvalidStateException", "pending deletion"));
      read(keyArn(kmsKey), kind, sealed(base(kind, kmsKey), kmsKey));
      harness.nativeAws.kms().clearFailures();
      harness.nativeAws.dynamoDb().fail("GetItem", ServiceError.of("com.amazonaws.dynamodb.v20120810#RequestLimitExceeded", "limit"));
      read(keyArn(kmsKey), kind, sealed(base(kind, kmsKey), kmsKey));
      harness.nativeAws.dynamoDb().clearFailures();
    }
  }

  @Test
  void requestedIdsAndVersions() {
    // GetItem for these finds nothing; the reads do not check them first.
    for (String id : Arrays.asList("", "\ud83d\ude00", "with space")) {
      for (Kind kind : Kind.values()) {
        readAs(keyArn(kmsKey), kind, id, VERSION, null, false);
      }
    }
    for (String version : Arrays.asList("", "x", "branch:version:" + VERSION)) {
      readAs(keyArn(kmsKey), Kind.VERSION, ID, version, null, false);
    }
    // The empty version asks for type "branch:version:", which no valid item has, with or without a version attribute.
    for (boolean withVersion : new boolean[] { false, true }) {
      Map<String, AttributeValue> item = base(Kind.VERSION, kmsKey);
      item.put("type", s("branch:version:"));
      if (withVersion) {
        item.put("version", s("branch:version:" + VERSION));
      }
      readAs(keyArn(kmsKey), Kind.VERSION, ID, "", sealed(item, kmsKey), true);
    }
    // An item whose empty id matches the empty id asked for.
    for (Kind kind : Kind.values()) {
      Map<String, AttributeValue> item = base(kind, kmsKey);
      item.put("branch-key-id", s(""));
      readAs(keyArn(kmsKey), kind, "", VERSION, sealed(item, kmsKey), true);
    }
  }

  // The SDK sends a lone surrogate to KMS as '?', so these items decrypt; the materials then fail, as UTF-8 cannot hold them.
  @Test
  void loneSurrogatesInStoredStrings() {
    Map<String, AttributeValue> version = base(Kind.VERSION, kmsKey);
    version.put("type", s("branch:version:\uD800"));
    readAs(keyArn(kmsKey), Kind.VERSION, ID, "\uD800", sealed(version, kmsKey), true);
    for (Kind kind : Kind.values()) {
      Map<String, AttributeValue> customKey = base(kind, kmsKey);
      customKey.put("aws-crypto-ec:\uD800", s("v"));
      read(keyArn(kmsKey), kind, sealed(customKey, kmsKey));
      Map<String, AttributeValue> customValue = base(kind, kmsKey);
      customValue.put("aws-crypto-ec:k", s("\uDC00"));
      read(keyArn(kmsKey), kind, sealed(customValue, kmsKey));
    }
    Map<String, AttributeValue> active = base(Kind.ACTIVE, kmsKey);
    active.put("version", s("branch:version:\uDC00"));
    read(keyArn(kmsKey), Kind.ACTIVE, sealed(active, kmsKey));
  }

  private void read(KMSConfiguration configuration, Kind kind, Map<String, AttributeValue> item) {
    readAs(configuration, kind, ID, VERSION, item, true);
  }

  // Answers GetItem with {@code item} (null: no item) when {@code replace}, else with what the table holds.
  private void readAs(KMSConfiguration configuration, Kind kind, String id, String version, Map<String, AttributeValue> item, boolean replace) {
    served = item;
    KeyStoreHarness.Stores stores = KeyStoreHarness.stores(config(configuration, kms, replace ? serving : ddb).build());
    harness.clearRequests();
    switch (kind) {
      case ACTIVE:
        stores.same("GetActiveBranchKey", GetActiveBranchKeyInput.builder().branchKeyIdentifier(id).build());
        if (configuration.kmsKeyArn() != null || configuration.kmsMRKeyArn() != null) {
          // VersionKey starts with the same read of the ACTIVE item, then authenticates it with ReEncrypt.
          stores.same("VersionKey", VersionKeyInput.builder().branchKeyIdentifier(id).build());
        }
        break;
      case VERSION:
        stores.same("GetBranchKeyVersion", GetBranchKeyVersionInput.builder().branchKeyIdentifier(id).branchKeyVersion(version).build());
        break;
      default:
        stores.same("GetBeaconKey", GetBeaconKeyInput.builder().branchKeyIdentifier(id).build());
    }
    harness.assertSameRequests();
  }

  private Map<String, AttributeValue> base(Kind kind, String storedArn) {
    Map<String, AttributeValue> item = new LinkedHashMap<>();
    item.put("branch-key-id", s(ID));
    switch (kind) {
      case ACTIVE:
        item.put("type", s("branch:ACTIVE"));
        item.put("version", s("branch:version:" + VERSION));
        break;
      case VERSION:
        item.put("type", s("branch:version:" + VERSION));
        break;
      default:
        item.put("type", s("beacon:ACTIVE"));
    }
    item.put("create-time", s(TIMESTAMP));
    item.put("hierarchy-version", n("1"));
    item.put("kms-arn", s(storedArn));
    item.put("aws-crypto-ec:tenant", s("a"));
    item.put("aws-crypto-ec:", s("empty key"));
    return item;
  }

  private Map<String, AttributeValue> sealed(Map<String, AttributeValue> item, String kmsArn) {
    return sealed(item, kmsArn, 32);
  }

  private Map<String, AttributeValue> sealed(Map<String, AttributeValue> item, String kmsArn, int length) {
    return sealed(item, kmsArn, length, LOGICAL_NAME);
  }

  // The item with "enc" set to a fresh key wrapped under the context the key store builds from the item.
  // Items that no context can describe get a placeholder.
  private Map<String, AttributeValue> sealed(Map<String, AttributeValue> item, String kmsArn, int length, String logicalName) {
    Map<String, String> context = new HashMap<>();
    for (Map.Entry<String, AttributeValue> entry : item.entrySet()) {
      AttributeValue value = entry.getValue();
      if (value.type() == AttributeValue.Type.S) {
        context.put(entry.getKey(), value.s());
      } else if (value.type() == AttributeValue.Type.N) {
        context.put(entry.getKey(), value.n());
      }
    }
    context.put("tablename", logicalName);
    Map<String, AttributeValue> result = new LinkedHashMap<>(item);
    SdkBytes wrapped;
    try {
      wrapped = setupKms
        .generateDataKeyWithoutPlaintext(r -> r.keyId(kmsArn).numberOfBytes(length).encryptionContext(context))
        .ciphertextBlob();
    } catch (RuntimeException e) {
      wrapped = SdkBytes.fromByteArray(new byte[] { 1, 2, 3 });
    }
    result.put("enc", AttributeValue.builder().b(wrapped).build());
    return result;
  }

  private static AttributeValue s(String value) {
    return AttributeValue.builder().s(value).build();
  }

  private static AttributeValue n(String value) {
    return AttributeValue.builder().n(value).build();
  }

  private static AttributeValue b(byte[] value) {
    return AttributeValue.builder().b(SdkBytes.fromByteArray(value)).build();
  }

  private static String repeat(char c, int count) {
    char[] chars = new char[count];
    Arrays.fill(chars, c);
    return new String(chars);
  }
}
