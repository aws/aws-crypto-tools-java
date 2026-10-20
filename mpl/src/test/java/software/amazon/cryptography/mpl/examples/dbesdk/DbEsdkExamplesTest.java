// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples.dbesdk;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.fakeaws.FakeKms;
import software.amazon.cryptography.materialproviders.fakeaws.RecordedRequest;
import software.amazon.cryptography.mpl.AlgorithmSuite;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptedDataKey;
import software.amazon.cryptography.mpl.EncryptionContext;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.SecretBytes;
import software.amazon.cryptography.mpl.cache.CacheEntry;
import software.amazon.cryptography.mpl.cache.CacheType;
import software.amazon.cryptography.mpl.cache.CryptographicMaterialsCache;
import software.amazon.cryptography.mpl.cache.DeleteCacheEntryRequest;
import software.amazon.cryptography.mpl.cache.DeleteCacheEntryResponse;
import software.amazon.cryptography.mpl.cache.GetCacheEntryRequest;
import software.amazon.cryptography.mpl.cache.GetCacheEntryResponse;
import software.amazon.cryptography.mpl.cache.PutCacheEntryRequest;
import software.amazon.cryptography.mpl.cache.PutCacheEntryResponse;
import software.amazon.cryptography.mpl.examples.dbesdk.DbEsdkLikeItemEncryptor.ParsedHeader;
import software.amazon.cryptography.mpl.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.keyrings.AesWrappingAlg;
import software.amazon.cryptography.mpl.keyrings.ClientSupplier;
import software.amazon.cryptography.mpl.keyrings.RawAesKeyring;
import software.amazon.cryptography.mpl.keystore.BeaconKeyMaterials;
import software.amazon.cryptography.mpl.keystore.BranchKeyStore;
import software.amazon.cryptography.mpl.keystore.KmsConfiguration;

// Runs every DB-ESDK example against the in-process fake AWS endpoint, and checks what each example claims.
class DbEsdkExamplesTest {

  private static final String WEST = "us-west-2";
  private static final String EAST = "us-east-1";

  private final FakeAws aws = FakeAws.start();
  private final ClientSupplier fakeClients = region -> aws.kmsClient("native", region);

  @AfterEach
  void close() {
    aws.close();
  }

  // --- customer examples ---

  @Test
  void mrkMultiKeyringDecryptsWithTheReplicaInAnotherRegion() {
    List<String> mrk = aws.kms().createMultiRegionKey(WEST, EAST);
    Map<String, String> encrypted = MrkMultiKeyringExample.encryptAndDecryptInAnotherRegion(mrk.get(0), mrk.get(1), fakeClients);

    ParsedHeader header = DbEsdkLikeItemEncryptor.parseHeader(encrypted);
    assertEquals(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384, header.algorithmSuite());
    EncryptedDataKey edk = header.encryptedDataKeys().get(0);
    assertEquals("aws-kms", edk.keyProviderId());
    assertEquals(mrk.get(0), new String(edk.keyProviderInfo(), StandardCharsets.UTF_8));
    assertEquals(Collections.singletonList(EAST), regions(operations("Decrypt")));
    assertFalse(encrypted.get(ExampleItems.SENSITIVE).contains("encrypt and sign me"));
  }

  @Test
  void hierarchicalKeyringUsesEachTenantsBranchKey() {
    String kmsKey = aws.kms().createSymmetricKey(WEST);
    List<Map<String, String>> encrypted = HierarchicalKeyringExample.encryptAndDecryptForTwoTenants(
      aws.dynamoDbClient("native", WEST),
      aws.kmsClient("native", WEST),
      "KeyStoreTable",
      "logical",
      kmsKey
    );
    EncryptedDataKey tenant1 = DbEsdkLikeItemEncryptor.parseHeader(encrypted.get(0)).encryptedDataKeys().get(0);
    EncryptedDataKey tenant2 = DbEsdkLikeItemEncryptor.parseHeader(encrypted.get(1)).encryptedDataKeys().get(0);
    assertEquals("aws-kms-hierarchy", tenant1.keyProviderId());
    assertFalse(Arrays.equals(tenant1.keyProviderInfo(), tenant2.keyProviderInfo()));
  }

  @Test
  void singleKeyStoreBeaconIsStableAndPerKey() {
    BranchKeyStore store = keyStore();
    String first = store.createKey().branchKeyIdentifier();
    String second = store.createKey().branchKeyIdentifier();
    String beacon = SearchableEncryptionExample.singleKeyStoreBeacon(store, first, "4321");
    assertEquals(beacon, SearchableEncryptionExample.singleKeyStoreBeacon(store, first, "4321"));
    Map<String, String> perTenant = SearchableEncryptionExample.multiKeyStoreBeacons(store, first, second, "4321");
    assertEquals(beacon, perTenant.get(first));
    assertEquals(3, perTenant.get(second).length());
    // The 10-bit beacons of two keys can collide; their 64-byte HMAC keys cannot.
    BeaconKeySource source = BeaconKeySource.multiKeyStore(store, "k").beaconNames(Collections.singletonList("b")).cacheTtlSeconds(60).build();
    assertFalse(source.hmacKeys(first).get("b").contentEquals(source.hmacKeys(second).get("b")));
  }

  @Test
  void rawEcdhStaticAndEphemeralSendersReachTheRecipient() throws Exception {
    List<Map<String, String>> encrypted = RawEcdhKeyringExample.encryptAndDecrypt(ecKeyPair(), ecKeyPair());
    for (Map<String, String> item : encrypted) {
      assertEquals("raw-ecdh", DbEsdkLikeItemEncryptor.parseHeader(item).encryptedDataKeys().get(0).keyProviderId());
    }
  }

  @Test
  void kmsEcdhRecipientDecryptsWithItsOwnKey() {
    String sender = aws.kms().createEccKeyAgreementKey(WEST, "ECC_NIST_P256");
    String recipient = aws.kms().createEccKeyAgreementKey(WEST, "ECC_NIST_P256");
    Map<String, String> encrypted = KmsEcdhKeyringExample.encryptAndDecrypt(aws.kmsClient("native", WEST), sender, recipient);
    assertEquals("aws-kms-ecdh", DbEsdkLikeItemEncryptor.parseHeader(encrypted).encryptedDataKeys().get(0).keyProviderId());
  }

  @Test
  void rawAesStoresNamespaceAndName() {
    Map<String, String> encrypted = RawAesKeyringExample.encryptAndDecrypt(SecretBytes.random(32));
    EncryptedDataKey edk = DbEsdkLikeItemEncryptor.parseHeader(encrypted).encryptedDataKeys().get(0);
    assertEquals("my-key-namespace", edk.keyProviderId());
    assertTrue(new String(edk.keyProviderInfo(), StandardCharsets.ISO_8859_1).startsWith("my-aes-key-name"));
  }

  @Test
  void rawRsaPublicKeyOnlyEncrypts() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    Map<String, String> encrypted = RawRsaKeyringExample.encryptAndDecrypt(generator.generateKeyPair());
    assertEquals("my-key-namespace", DbEsdkLikeItemEncryptor.parseHeader(encrypted).encryptedDataKeys().get(0).keyProviderId());
  }

  @Test
  void kmsRsaUsesTheSuiteWithoutEcdsa() throws Exception {
    String rsaKey = aws.kms().createRsaKey(WEST, "RSA_2048");
    Map<String, String> encrypted = KmsRsaKeyringExample.encryptAndDecrypt(aws.kmsClient("native", WEST), rsaKey);
    ParsedHeader header = DbEsdkLikeItemEncryptor.parseHeader(encrypted);
    assertEquals(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384, header.algorithmSuite());
    assertEquals("aws-kms-rsa", header.encryptedDataKeys().get(0).keyProviderId());
    // One HMAC-SHA-384 recipient tag and no signature.
    assertEquals(48, java.util.Base64.getDecoder().decode(encrypted.get(DbEsdkLikeItemEncryptor.FOOTER)).length);
  }

  @Test
  void multiKeyringWritesOneDataKeyPerKeyring() {
    String kmsKey = aws.kms().createSymmetricKey(WEST);
    Map<String, String> encrypted = MultiKeyringExample.encryptAndDecryptWithEitherKey(aws.kmsClient("native", WEST), kmsKey, SecretBytes.random(32));
    List<String> providers = new ArrayList<>();
    for (EncryptedDataKey edk : DbEsdkLikeItemEncryptor.parseHeader(encrypted).encryptedDataKeys()) {
      providers.add(edk.keyProviderId());
    }
    assertEquals(Arrays.asList("aws-kms", "my-key-namespace"), providers);
  }

  @Test
  void mrkDiscoveryDecryptsInItsRegionAndReportsFilteredKeys() {
    List<String> mrk = aws.kms().createMultiRegionKey(WEST, EAST);
    Map<String, String> encrypted = MrkMultiKeyringExample.encryptAndDecryptInAnotherRegion(mrk.get(0), mrk.get(1), fakeClients);
    aws.clearRequests();

    Map<String, String> decrypted = MrkDiscoveryMultiKeyringExample.decrypt(encrypted, EAST, Collections.singletonList(FakeKms.ACCOUNT), fakeClients);
    assertEquals(ExampleItems.item("mrkMultiKeyringItem"), decrypted);
    assertEquals(Collections.singletonList(EAST), regions(operations("Decrypt")));

    aws.clearRequests();
    List<Throwable> failures = MrkDiscoveryMultiKeyringExample.whyDecryptFailed(
      encrypted,
      EAST,
      Collections.singletonList("000000000000"),
      fakeClients
    );
    assertEquals(1, failures.size());
    assertInstanceOf(NoMatchingDataKeyException.class, failures.get(0));
    assertTrue(operations("Decrypt").isEmpty());
  }

  @Test
  void regionalRoleSupplierUsesEachRegionsRole() {
    List<String> mrk = aws.kms().createMultiRegionKey(WEST, EAST);
    Map<String, String> roles = new HashMap<>();
    roles.put(WEST, "role-west");
    roles.put(EAST, "role-east");
    ClientSupplier supplier = new ClientSupplierExample.RegionalRoleClientSupplier(roles, (role, region) -> aws.kmsClient(role, region));

    ClientSupplierExample.encryptAndDecrypt(mrk.get(0), EAST, FakeKms.ACCOUNT, supplier);
    assertEquals(Collections.singletonList("GenerateDataKey"), operationsOf("role-west"));
    assertEquals(Collections.singletonList("Decrypt"), operationsOf("role-east"));

    ClientSupplier westOnly = new ClientSupplierExample.RegionalRoleClientSupplier(
      Collections.singletonMap(WEST, "role-west"),
      (role, region) -> aws.kmsClient(role, region)
    );
    IllegalArgumentException e = assertThrows(
      IllegalArgumentException.class,
      () -> ClientSupplierExample.encryptAndDecrypt(mrk.get(0), EAST, FakeKms.ACCOUNT, westOnly)
    );
    assertEquals("Missing region " + EAST, e.getMessage());
  }

  @Test
  void headersStoreNoBaseOrSignAndIncludeEntries() {
    BranchKeyStore store = keyStore();
    Map<String, String> encrypted = RequiredEncryptionContextExample.encryptAndDecrypt(store);
    Map<String, String> stored = DbEsdkLikeItemEncryptor.parseHeader(encrypted).storedEncryptionContext();
    // As in the Dafny item encryptor, every base context and version-2 entry is required,
    // so the header stores only the signing suite's public key.
    assertEquals(Collections.singleton("aws-crypto-public-key"), stored.keySet());
    // Version 1 (SIGN_ONLY key attributes): the base context also holds the key values, and they are required too.
    Map<String, String> version1 = ExampleItems.roundTrip(ExampleItems.encryptor(aesKeyring()), ExampleItems.item("tenant"));
    assertEquals(Collections.singleton("aws-crypto-public-key"), DbEsdkLikeItemEncryptor.parseHeader(version1).storedEncryptionContext().keySet());

    // The failure comes from the context alone: the branch key is the same.
    assertInstanceOf(NoMatchingDataKeyException.class, RequiredEncryptionContextExample.decryptAfterChangingSortKey(store));
  }

  @Test
  void oneCacheServesTwoKeyringsAndTheBeaconKeySource() {
    BranchKeyStore store = keyStore();
    String branchKey = store.createKey().branchKeyIdentifier();
    aws.clearRequests();
    String beacon = SharedCacheExample.shareOneCache(store, branchKey);
    // Active branch key, the version on the writer's decrypt, the beacon key; the reader's decrypt hits the cache.
    assertEquals(3, operations("Decrypt").size());
    assertEquals(3, beacon.length());
  }

  // --- integration examples ---

  @Test
  void resolverRequestsMatchTheDafnyDbEsdk() {
    RawAesKeyring keyring = aesKeyring();
    NativeMplMaterialResolver resolver = NativeMplMaterialResolver.forKeyring(keyring);
    Map<String, byte[]> base = Collections.singletonMap("aws-crypto-table-name", bytes("T"));
    Map<String, byte[]> v2 = new LinkedHashMap<>();
    v2.put("aws-crypto-legend", bytes("SS"));
    v2.put("aws-crypto-attr.b", bytes("1"));
    v2.put("aws-crypto-attr.a", bytes("2"));

    EncryptionMaterials encryption = resolver.forEncrypt(base, v2, null, 10);
    assertEquals(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384, encryption.algorithmSuite());
    // StructuredEncryption's version-2 keys, then the item encryptor's base keys, as the nested managers add them.
    assertEquals(
      Arrays.asList("aws-crypto-attr.a", "aws-crypto-attr.b", "aws-crypto-legend", "aws-crypto-table-name"),
      encryption.requiredEncryptionContextKeys()
    );
    assertEquals(encryption.encryptedDataKeys().size(), encryption.symmetricSigningKeys().size());
    assertEquals(384, ((ECPrivateKey) encryption.signingPrivateKey().get()).getParams().getCurve().getField().getFieldSize());

    DecryptionMaterials decryption = resolver.forDecrypt(
      encryption.algorithmSuite(),
      encryption.encryptedDataKeys(),
      NativeMplMaterialResolver.toByteContext(withoutRequired(encryption)),
      base,
      v2
    );
    assertTrue(decryption.plaintextDataKey().get().contentEquals(encryption.plaintextDataKey().get()));
    assertTrue(decryption.symmetricSigningKey().get().contentEquals(encryption.symmetricSigningKeys().get(0)));
    assertTrue(decryption.verificationPublicKey().isPresent());

    Map<String, byte[]> wrongV2 = new LinkedHashMap<>(v2);
    wrongV2.put("aws-crypto-attr.a", bytes("3"));
    assertThrows(
      NoMatchingDataKeyException.class,
      () -> resolver.forDecrypt(
        encryption.algorithmSuite(),
        encryption.encryptedDataKeys(),
        NativeMplMaterialResolver.toByteContext(withoutRequired(encryption)),
        base,
        wrongV2
      )
    );
  }

  @Test
  void resolverRejectsBytesThatAreNotUtf8() {
    byte[] notUtf8 = { (byte) 0xC3 };
    assertThrows(ValidationException.class, () -> EncryptionContext.fromUtf8(Collections.singletonMap("k", notUtf8)));
    assertThrows(ValidationException.class, () -> EncryptedDataKey.ofUtf8(notUtf8, new byte[0], new byte[0]));
  }

  // The values the native DB-ESDK's test server hard-codes for both DBE suites.
  @Test
  void suiteCatalogueMatchesTheDbEsdkConstants() {
    for (byte flavor : new byte[] { 0x00, 0x01 }) {
      AlgorithmSuite suite = DbeSuiteFacts.fromFlavor(flavor);
      assertEquals(flavor, DbeSuiteFacts.flavor(suite));
      assertEquals(flavor == 0x01, suite.isSigning());
      assertEquals("HmacSHA512", suite.keyDerivation().hmacAlgorithm().get());
      assertEquals("HmacSHA512", suite.commitmentHmacAlgorithm().get());
      assertEquals("HmacSHA384", suite.symmetricSignatureHmacAlgorithm().get());
      assertEquals(32, suite.dataKeyLength());
      assertEquals(32, suite.commitmentKeyLength());
    }
    assertThrows(ValidationException.class, () -> DbeSuiteFacts.fromFlavor((byte) 0x02));
  }

  // Golden vectors from the Dafny DB-ESDK test/Beacon.dfy TestOneBeaconValue, base key [1, 2, 3, 4, 5].
  @Test
  void beaconDerivationMatchesTheDafnyDbEsdk() {
    SecretBytes base = SecretBytes.copyOf(new byte[] { 1, 2, 3, 4, 5 });
    assertEquals("7d9bfa40", SearchableEncryptionExample.standardBeacon(BeaconKeySource.hmacKey(base, "Name"), "MyName", 32));
    assertEquals("0e9064", SearchableEncryptionExample.standardBeacon(BeaconKeySource.hmacKey(base, "std4"), "abc", 24));
    assertEquals("2d99222", SearchableEncryptionExample.standardBeacon(BeaconKeySource.hmacKey(base, "std6"), "666", 26));
  }

  @Test
  void beaconKeySourceCachesWithinItsTtlAndPartition() {
    BranchKeyStore store = keyStore();
    String key = store.createKey().branchKeyIdentifier();
    CryptographicMaterialsCache backing = CryptographicMaterialsCache.create(CacheType.multiThreaded(10));
    List<CacheEntry> puts = new ArrayList<>();
    CryptographicMaterialsCache cache = new CryptographicMaterialsCache() {
      @Override
      public GetCacheEntryResponse getCacheEntry(GetCacheEntryRequest request) {
        return backing.getCacheEntry(request);
      }

      @Override
      public PutCacheEntryResponse putCacheEntry(PutCacheEntryRequest request) {
        puts.add(request.entry());
        return backing.putCacheEntry(request);
      }

      @Override
      public DeleteCacheEntryResponse deleteCacheEntry(DeleteCacheEntryRequest request) {
        return backing.deleteCacheEntry(request);
      }
    };
    // The built-in cache expires entries by the system clock, so the source's clock starts there.
    AtomicLong now = new AtomicLong(System.currentTimeMillis() / 1000);
    BeaconKeySource source = beaconSource(store, key, cache, "p", now);
    aws.clearRequests();

    Map<String, SecretBytes> firstKeys = source.hmacKeys(key);
    byte[] first = firstKeys.get("b").toByteArray();
    // The caller owns what it gets: destroying it leaves the cached keys intact.
    firstKeys.get("b").destroy();
    now.addAndGet(60);
    Map<String, SecretBytes> hit = source.hmacKeys(key);
    assertArrayEquals(first, hit.get("b").toByteArray());
    hit.get("b").destroy();
    assertArrayEquals(first, source.hmacKeys(key).get("b").toByteArray());
    assertEquals(1, operations("Decrypt").size());
    // As in the Dafny DB-ESDK, the cache holds the derived keys and not the beacon key.
    BeaconKeyMaterials cached = puts.get(0).beaconKeyMaterials().get();
    assertFalse(cached.beaconKey().isPresent());
    assertArrayEquals(first, cached.hmacKeys().get("b").toByteArray());

    now.addAndGet(1);
    source.hmacKeys(key);
    assertEquals(2, operations("Decrypt").size());

    beaconSource(store, key, cache, "p", now).hmacKeys(key);
    assertEquals(2, operations("Decrypt").size());
    beaconSource(store, key, cache, "q", now).hmacKeys(key);
    assertEquals(3, operations("Decrypt").size());
  }

  private static BeaconKeySource beaconSource(BranchKeyStore store, String key, CryptographicMaterialsCache cache, String partitionId, AtomicLong now) {
    return BeaconKeySource
      .singleKeyStore(store, key)
      .beaconNames(Collections.singletonList("b"))
      .cacheTtlSeconds(60)
      .cache(CacheType.shared(cache))
      .partitionId(partitionId)
      .clock(now::get)
      .build();
  }

  // The stand-in must actually check what it authenticates, or the round trips above would prove nothing.
  @Test
  void standInRejectsTamperedItems() {
    DbEsdkLikeItemEncryptor encryptor = ExampleItems.encryptor(aesKeyring());
    Map<String, String> encrypted = encryptor.encryptItem(ExampleItems.item("tamper"));

    Map<String, String> otherCiphertext = new LinkedHashMap<>(encrypted);
    otherCiphertext.put(ExampleItems.SENSITIVE, encryptor.encryptItem(ExampleItems.item("tamper")).get(ExampleItems.SENSITIVE));
    assertThrows(DbEsdkLikeItemEncryptor.TamperedItemException.class, () -> encryptor.decryptItem(otherCiphertext));

    // Without ECDSA, only the recipient tag protects the signed attributes.
    DbEsdkLikeItemEncryptor unsigned = DbEsdkLikeItemEncryptor
      .builder()
      .logicalTableName(ExampleItems.TABLE)
      .partitionKeyName(ExampleItems.PARTITION_KEY)
      .sortKeyName(ExampleItems.SORT_KEY)
      .attributeActionsOnEncrypt(ExampleItems.actions())
      .keyring(aesKeyring())
      .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384)
      .build();
    Map<String, String> unsignedItem = unsigned.encryptItem(ExampleItems.item("tamper"));
    byte[] footer = java.util.Base64.getDecoder().decode(unsignedItem.get(DbEsdkLikeItemEncryptor.FOOTER));
    footer[0] ^= 1;
    Map<String, String> otherTag = new LinkedHashMap<>(unsignedItem);
    otherTag.put(DbEsdkLikeItemEncryptor.FOOTER, java.util.Base64.getEncoder().encodeToString(footer));
    assertThrows(DbEsdkLikeItemEncryptor.TamperedItemException.class, () -> unsigned.decryptItem(otherTag));

    // A changed key value changes the required context the data key was wrapped with: the item was edited or moved.
    Map<String, String> otherSortKey = new LinkedHashMap<>(encrypted);
    otherSortKey.put(ExampleItems.SORT_KEY, "1");
    assertThrows(NoMatchingDataKeyException.class, () -> encryptor.decryptItem(otherSortKey));
  }

  private BranchKeyStore keyStore() {
    BranchKeyStore store = BranchKeyStore
      .builder()
      .ddbTableName("KeyStoreTable")
      .logicalKeyStoreName("logical")
      .kmsConfiguration(KmsConfiguration.kmsKeyArn(aws.kms().createSymmetricKey(WEST)))
      .kmsClient(aws.kmsClient("native", WEST))
      .ddbClient(aws.dynamoDbClient("native", WEST))
      .build();
    store.createKeyStore();
    return store;
  }

  private static RawAesKeyring aesKeyring() {
    return RawAesKeyring.builder().keyNamespace("ns").keyName("name").wrappingKey(SecretBytes.random(32)).wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16).build();
  }

  private static Map<String, String> withoutRequired(EncryptionMaterials materials) {
    Map<String, String> stored = new LinkedHashMap<>(materials.encryptionContext());
    stored.keySet().removeAll(materials.requiredEncryptionContextKeys());
    return stored;
  }

  private static KeyPair ecKeyPair() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    return generator.generateKeyPair();
  }

  private List<RecordedRequest> operations(String operation) {
    List<RecordedRequest> selected = new ArrayList<>();
    for (RecordedRequest request : aws.requests()) {
      if (request.service().equals("kms") && request.operation().equals(operation)) {
        selected.add(request);
      }
    }
    return selected;
  }

  private List<String> operationsOf(String label) {
    List<String> names = new ArrayList<>();
    for (RecordedRequest request : aws.requests(label)) {
      names.add(request.operation());
    }
    return names;
  }

  private static List<String> regions(List<RecordedRequest> requests) {
    List<String> regions = new ArrayList<>();
    for (RecordedRequest request : requests) {
      regions.add(request.region());
    }
    return regions;
  }

  private static byte[] bytes(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }
}
