// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.materialproviders.KeyStoreHarness.discovery;
import static software.amazon.cryptography.materialproviders.KeyStoreHarness.keyArn;
import static software.amazon.cryptography.materialproviders.KeyStoreHarness.mrDiscovery;
import static software.amazon.cryptography.materialproviders.KeyStoreHarness.mrKeyArn;
import static software.amazon.cryptography.materialproviders.KeyringTests.array;
import static software.amazon.cryptography.materialproviders.KeyringTests.decryptionMaterials;
import static software.amazon.cryptography.materialproviders.KeyringTests.edk;
import static software.amazon.cryptography.materialproviders.KeyringTests.encryptionMaterials;
import static software.amazon.cryptography.materialproviders.KeyringTests.flip;
import static software.amazon.cryptography.materialproviders.KeyringTests.map;
import static software.amazon.cryptography.materialproviders.RealChecks.KMS;
import static software.amazon.cryptography.materialproviders.RealChecks.assertCmmRoundTrip;
import static software.amazon.cryptography.materialproviders.RealChecks.assertEachDecrypts;
import static software.amazon.cryptography.materialproviders.RealChecks.assertEachFails;
import static software.amazon.cryptography.materialproviders.RealChecks.assertSameDecrypt;
import static software.amazon.cryptography.materialproviders.RealChecks.assertSameEncrypt;
import static software.amazon.cryptography.materialproviders.RealChecks.encryptedByBoth;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.CreateKeyInput;
import software.amazon.cryptography.keystore.model.CreateKeyOutput;
import software.amazon.cryptography.keystore.model.CreateKeyStoreInput;
import software.amazon.cryptography.keystore.model.GetActiveBranchKeyInput;
import software.amazon.cryptography.keystore.model.GetBeaconKeyInput;
import software.amazon.cryptography.keystore.model.GetBranchKeyVersionInput;
import software.amazon.cryptography.keystore.model.KMSConfiguration;
import software.amazon.cryptography.keystore.model.KeyStoreConfig;
import software.amazon.cryptography.keystore.model.VersionKeyInput;
import software.amazon.cryptography.materialproviders.KeyStoreHarness.Stores;
import software.amazon.cryptography.materialproviders.KeyringTests.Outcomes;
import software.amazon.cryptography.materialproviders.KeyringTests.Pair;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsHierarchicalKeyringInput;
import software.amazon.cryptography.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.model.EncryptionMaterials;

// The key store and the hierarchical keyring, native and reference, over one real DynamoDB table and the symmetric KMS key.
// Both sides read the same items, so key store results compare exactly (random ids and times masked),
// and each side reads and decrypts with the branch keys the other created.
class RealKeyStoreIT {

  private static RealAws aws;
  private static KmsClient kms;
  private static DynamoDbClient ddb;
  private static Stores stores;
  /** Branch keys this run created: one by each side, and one with a caller-chosen id. */
  private static String nativeKey;
  private static String referenceKey;
  private static String namedKey;

  private final Object reference = ReferenceMpl.materialProviders();
  private final Outcomes outcomes = new Outcomes();

  @BeforeAll
  static void keyStore() {
    aws = RealAws.fromEnvironment();
    kms = aws.kms(aws.region);
    ddb = aws.dynamoDb(aws.region);
    stores = KeyStoreHarness.stores(config(keyArn(aws.sym), kms, ddb).build());
    ReferenceMpl.registerTwin(stores.nativeStore, stores.referenceStore);
    // The native store creates the table if this is the first run; both then see it exist.
    System.out.println("native CreateKeyStore: " + KeyStoreHarness.outcome(() -> stores.nativeStore.CreateKeyStore(CreateKeyStoreInput.builder().build())));
    ddb.waiter().waitUntilTableExists(r -> r.tableName(RealAws.TABLE));
    String created = same(stores, "CreateKeyStore", CreateKeyStoreInput.builder().build());
    assertTrue(created.contains(":table/" + RealAws.TABLE), created);

    CreateKeyInput random = CreateKeyInput.builder().build();
    CreateKeyOutput nativeCreated = stores.nativeStore.CreateKey(random);
    CreateKeyOutput referenceCreated = (CreateKeyOutput) ReferenceMpl.fromReference(ReferenceMpl.call(stores.referenceStore, "CreateKey", random));
    assertEquals(KeyStoreHarness.mask(ReferenceMpl.describe(referenceCreated)), KeyStoreHarness.mask(ReferenceMpl.describe(nativeCreated)));
    nativeKey = nativeCreated.branchKeyIdentifier();
    referenceKey = referenceCreated.branchKeyIdentifier();
    namedKey = "mpl-native-java-it-" + UUID.randomUUID();
    stores.nativeStore.CreateKey(CreateKeyInput.builder().branchKeyIdentifier(namedKey).encryptionContext(map("purpose", "integration test")).build());
    for (String key : Arrays.asList(nativeKey, referenceKey, namedKey)) {
      System.out.println("created branch key " + key);
    }
  }

  @AfterAll
  static void close() {
    aws.close();
  }

  @Test
  void eachSideReadsWhatTheOtherCreated() {
    same(stores, "GetKeyStoreInfo", null);
    for (String key : Arrays.asList(nativeKey, referenceKey, namedKey)) {
      String active = same(stores, "GetActiveBranchKey", GetActiveBranchKeyInput.builder().branchKeyIdentifier(key).build());
      String version = stores.nativeStore.GetActiveBranchKey(GetActiveBranchKeyInput.builder().branchKeyIdentifier(key).build()).branchKeyMaterials().branchKeyVersion();
      String byVersion = same(stores, "GetBranchKeyVersion", GetBranchKeyVersionInput.builder().branchKeyIdentifier(key).branchKeyVersion(version).build());
      assertEquals(active.replace("GetActiveBranchKeyOutput", ""), byVersion.replace("GetBranchKeyVersionOutput", ""), key);
      assertFalse(same(stores, "GetBeaconKey", GetBeaconKeyInput.builder().branchKeyIdentifier(key).build()).startsWith("throws"), key);
    }
    // A caller-chosen id that exists: the conditional write fails on both sides, and nothing is written.
    CreateKeyInput again = CreateKeyInput.builder().branchKeyIdentifier(namedKey).encryptionContext(map("purpose", "again")).build();
    assertTrue(same(stores, "CreateKey", again).startsWith("throws"));
  }

  // Each side rotates the branch key the other created; the old version stays readable.
  @Test
  void versionKey() {
    for (String key : Arrays.asList(nativeKey, referenceKey)) {
      GetActiveBranchKeyInput activeInput = GetActiveBranchKeyInput.builder().branchKeyIdentifier(key).build();
      String before = stores.nativeStore.GetActiveBranchKey(activeInput).branchKeyMaterials().branchKeyVersion();
      VersionKeyInput input = VersionKeyInput.builder().branchKeyIdentifier(key).build();
      String rotated = key.equals(nativeKey)
        ? KeyStoreHarness.outcome(() -> ReferenceMpl.call(stores.referenceStore, "VersionKey", input))
        : KeyStoreHarness.outcome(() -> stores.nativeStore.VersionKey(input));
      assertFalse(rotated.startsWith("throws"), rotated);
      same(stores, "GetActiveBranchKey", activeInput);
      String after = stores.nativeStore.GetActiveBranchKey(activeInput).branchKeyMaterials().branchKeyVersion();
      assertNotEquals(before, after, key);
      same(stores, "GetBranchKeyVersion", GetBranchKeyVersionInput.builder().branchKeyIdentifier(key).branchKeyVersion(before).build());
    }
  }

  // What real DynamoDB and KMS refuse, through stores configured wrong in each way.
  @Test
  void failures() {
    String missingVersion = UUID.randomUUID().toString();
    assertTrue(same(stores, "GetBranchKeyVersion", GetBranchKeyVersionInput.builder().branchKeyIdentifier(nativeKey).branchKeyVersion(missingVersion).build()).startsWith("throws"));
    assertTrue(same(stores, "GetActiveBranchKey", GetActiveBranchKeyInput.builder().branchKeyIdentifier("no-such-branch-key").build()).startsWith("throws"));
    assertTrue(same(stores, "GetBeaconKey", GetBeaconKeyInput.builder().branchKeyIdentifier("no-such-branch-key").build()).startsWith("throws"));
    assertTrue(same(stores, "VersionKey", VersionKeyInput.builder().branchKeyIdentifier("no-such-branch-key").build()).startsWith("throws"));

    KmsClient otherRegion = aws.kms(aws.replicaRegion);
    Map<String, KeyStoreConfig> configs = new LinkedHashMap<>();
    configs.put("another KMS key", config(keyArn(aws.mrk), kms, ddb).build());
    configs.put("the replica as MRK key", config(mrKeyArn(aws.mrkReplica), otherRegion, ddb).build());
    configs.put("KMS client of another Region", config(keyArn(aws.sym), otherRegion, ddb).build());
    configs.put("MRK discovery in another Region", config(mrDiscovery(aws.replicaRegion), otherRegion, ddb).build());
    // The logical name is in the encryption context KMS checks.
    configs.put("another logical name", config(keyArn(aws.sym), kms, ddb).logicalKeyStoreName("other-logical-name").build());
    configs.put("missing table", config(keyArn(aws.sym), kms, ddb).ddbTableName(RealAws.TABLE + "-missing").build());
    for (Map.Entry<String, KeyStoreConfig> config : configs.entrySet()) {
      Stores wrong = KeyStoreHarness.stores(config.getValue());
      String active = same(wrong, "GetActiveBranchKey", GetActiveBranchKeyInput.builder().branchKeyIdentifier(nativeKey).build());
      assertTrue(active.startsWith("throws"), config.getKey() + ": " + active);
      same(wrong, "GetBeaconKey", GetBeaconKeyInput.builder().branchKeyIdentifier(nativeKey).build());
      // Fails before any write: at the item checks or at the first KMS call.
      String versioned = same(wrong, "VersionKey", VersionKeyInput.builder().branchKeyIdentifier(nativeKey).build());
      assertTrue(versioned.startsWith("throws"), config.getKey() + ": " + versioned);
      // The other configurations could create a branch key; these fail before writing one.
      if (config.getKey().equals("KMS client of another Region") || config.getKey().equals("MRK discovery in another Region")) {
        String created = same(wrong, "CreateKey", CreateKeyInput.builder().build());
        assertTrue(created.startsWith("throws"), config.getKey() + ": " + created);
      }
    }

    // Discovery reads with whatever key the item names; it cannot create or rotate keys.
    Stores discovering = KeyStoreHarness.stores(config(discovery(), kms, ddb).build());
    assertFalse(same(discovering, "GetActiveBranchKey", GetActiveBranchKeyInput.builder().branchKeyIdentifier(referenceKey).build()).startsWith("throws"));
    assertTrue(same(discovering, "VersionKey", VersionKeyInput.builder().branchKeyIdentifier(referenceKey).build()).startsWith("throws"));
    assertTrue(same(discovering, "CreateKey", CreateKeyInput.builder().build()).startsWith("throws"));
  }

  // A store given no clients builds its own from the default credential chain (the integrationTest task sets AWS_PROFILE).
  @Test
  void storeCreatedClients() {
    KeyStoreConfig noClients = config(keyArn(aws.sym), null, null).build();
    Stores own = KeyStoreHarness.stores(noClients);
    String active = same(own, "GetActiveBranchKey", GetActiveBranchKeyInput.builder().branchKeyIdentifier(namedKey).build());
    assertEquals(same(stores, "GetActiveBranchKey", GetActiveBranchKeyInput.builder().branchKeyIdentifier(namedKey).build()), active);
    same(own, "GetKeyStoreInfo", null);
  }

  @Test
  void hierarchicalKeyring() {
    Pair keyring = hierarchical(stores.nativeStore, nativeKey);
    Pair referenceKeysKeyring = hierarchical(stores.nativeStore, referenceKey);
    for (AlgorithmSuiteId suite : RealAws.SUITES) {
      for (boolean withDataKey : new boolean[] { false, true }) {
        EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), withDataKey);
        String context = ReferenceMpl.describe(suite) + " data key " + withDataKey;
        assertSameEncrypt(outcomes, keyring, start, KMS, context);
        List<EncryptionMaterials> results = encryptedByBoth(keyring, start);
        // A new keyring has an empty cache, so it reads the version from the table.
        assertEachDecrypts(outcomes, results, Arrays.asList(keyring, hierarchical(stores.nativeStore, nativeKey)), context);
        assertEachFails(outcomes, results, Collections.singletonList(referenceKeysKeyring), context);
        for (EncryptionMaterials result : results) {
          String otherContext = assertSameDecrypt(outcomes, keyring, decryptionMaterials(result, map("a", "c")), result.encryptedDataKeys(), context + " other context");
          assertTrue(otherContext.startsWith("throws"), otherContext);
          EncryptedDataKey edk = result.encryptedDataKeys().get(0);
          byte[] ciphertext = array(edk.ciphertext());
          // Salt, IV, branch key version (another version is not in the table), tag.
          for (int index : new int[] { 0, 16, 28, ciphertext.length - 1 }) {
            List<EncryptedDataKey> tampered = Collections.singletonList(edk("aws-kms-hierarchy", array(edk.keyProviderInfo()), flip(ciphertext, index)));
            String failed = assertSameDecrypt(outcomes, hierarchical(stores.nativeStore, nativeKey), decryptionMaterials(result), tampered, context + " byte " + index + " flipped");
            assertTrue(failed.startsWith("throws"), failed);
          }
        }
      }
      assertCmmRoundTrip(reference, outcomes, keyring, hierarchical(stores.nativeStore, nativeKey), suite, KMS, "hierarchical");
    }

    // Through stores whose KMS access fails: the branch key cannot be unwrapped on encrypt or decrypt.
    EncryptionMaterials encrypted = keyring.nativeEncrypt(encryptionMaterials(RealAws.DBE, map("a", "b"), false));
    for (KMSConfiguration kmsConfiguration : Arrays.asList(keyArn(aws.sym), keyArn(aws.mrk))) {
      KmsClient client = kmsConfiguration.kmsKeyArn().equals(aws.sym) ? aws.kms(aws.replicaRegion) : kms;
      Stores wrong = KeyStoreHarness.stores(config(kmsConfiguration, client, ddb).build());
      ReferenceMpl.registerTwin(wrong.nativeStore, wrong.referenceStore);
      Pair failing = hierarchical(wrong.nativeStore, nativeKey);
      String label = "store with " + kmsConfiguration.kmsKeyArn() + " and a client for " + (client == kms ? aws.region : aws.replicaRegion);
      assertTrue(assertSameEncrypt(outcomes, failing, encryptionMaterials(RealAws.DBE, map("a", "b"), false), KMS, label).startsWith("throws"));
      assertTrue(assertSameDecrypt(outcomes, failing, decryptionMaterials(encrypted), encrypted.encryptedDataKeys(), label).startsWith("throws"));
    }
    outcomes.assertBothSeen("OnDecrypt");
  }

  // After a rotation, new messages use the new version and old ones still decrypt.
  @Test
  void hierarchicalKeyringAcrossVersions() {
    String key = namedKey;
    List<EncryptionMaterials> old = new ArrayList<>(encryptedByBoth(hierarchical(stores.nativeStore, key), encryptionMaterials(RealAws.NON_COMMITTING, map("a", "b"), false)));
    stores.nativeStore.VersionKey(VersionKeyInput.builder().branchKeyIdentifier(key).build());
    Pair fresh = hierarchical(stores.nativeStore, key);
    EncryptionMaterials start = encryptionMaterials(RealAws.NON_COMMITTING, map("a", "b"), false);
    assertSameEncrypt(outcomes, fresh, start, KMS, "after rotation");
    List<EncryptionMaterials> current = encryptedByBoth(fresh, start);
    // The ciphertext is salt (16 bytes), IV (12), branch key version (16), wrapped key.
    assertFalse(
      Arrays.equals(versionIn(old.get(0)), versionIn(current.get(0))),
      "the version in the encrypted data key changed"
    );
    old.addAll(current);
    assertEachDecrypts(outcomes, old, Arrays.asList(fresh, hierarchical(stores.nativeStore, key)), "across versions");
  }

  // Logs each outcome: the run's output shows what the real services answered.
  private static String same(Stores pair, String operation, Object input) {
    String outcome = pair.same(operation, input);
    System.out.println("compared " + operation + " " + (outcome.length() <= 400 ? outcome : outcome.substring(0, 400) + "..."));
    return outcome;
  }

  private static byte[] versionIn(EncryptionMaterials materials) {
    return Arrays.copyOfRange(array(materials.encryptedDataKeys().get(0).ciphertext()), 28, 44);
  }

  private Pair hierarchical(KeyStore store, String branchKeyId) {
    CreateAwsKmsHierarchicalKeyringInput input = CreateAwsKmsHierarchicalKeyringInput.builder().keyStore(store).branchKeyId(branchKeyId).ttlSeconds(600).build();
    return new Pair(KeyringTests.MPL.CreateAwsKmsHierarchicalKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsHierarchicalKeyring", input));
  }

  private static KeyStoreConfig.Builder config(KMSConfiguration kmsConfiguration, KmsClient kmsClient, DynamoDbClient ddbClient) {
    return KeyStoreConfig
      .builder()
      .ddbTableName(RealAws.TABLE)
      .logicalKeyStoreName(RealAws.LOGICAL_NAME)
      .id(RealAws.LOGICAL_NAME)
      .kmsConfiguration(kmsConfiguration)
      .kmsClient(kmsClient)
      .ddbClient(ddbClient);
  }
}
