// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keyrings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.cache.CryptographicMaterialsCache;
import software.amazon.cryptography.materialproviders.cache.MultiThreadedCache;
import software.amazon.cryptography.materialproviders.examples.dbesdk.BeaconKeySource;
import software.amazon.cryptography.materialproviders.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.keystore.BeaconKeyMaterials;
import software.amazon.cryptography.materialproviders.keystore.BranchKeyMaterials;
import software.amazon.cryptography.materialproviders.keystore.DynamoDbKeyStore;
import software.amazon.cryptography.materialproviders.keystore.GetActiveBranchKeyRequest;
import software.amazon.cryptography.materialproviders.keystore.GetActiveBranchKeyResponse;
import software.amazon.cryptography.materialproviders.keystore.GetBeaconKeyRequest;
import software.amazon.cryptography.materialproviders.keystore.GetBeaconKeyResponse;
import software.amazon.cryptography.materialproviders.keystore.GetBranchKeyVersionRequest;
import software.amazon.cryptography.materialproviders.keystore.GetBranchKeyVersionResponse;
import software.amazon.cryptography.materialproviders.keystore.GetKeyStoreInfoRequest;
import software.amazon.cryptography.materialproviders.keystore.GetKeyStoreInfoResponse;
import software.amazon.cryptography.materialproviders.keystore.KeyStore;
import software.amazon.cryptography.materialproviders.keystore.KmsConfiguration;

// KeyStore implementations a customer writes, used by the hierarchical keyring through the interface only.
class CustomKeyStoreTest {

  private static final String REGION = "us-west-2";

  private final FakeAws aws = FakeAws.start();
  private final DynamoDbKeyStore dynamoDb = DynamoDbKeyStore
    .builder()
    .ddbTableName("KeyStoreTable")
    .logicalKeyStoreName("logical")
    .kmsConfiguration(KmsConfiguration.kmsKeyArn(aws.kms().createSymmetricKey(REGION)))
    .kmsClient(aws.kmsClient("native", REGION))
    .ddbClient(aws.dynamoDbClient("native", REGION))
    .build();
  private final String branchKeyId;

  CustomKeyStoreTest() {
    dynamoDb.createKeyStore();
    branchKeyId = dynamoDb.createKey().branchKeyId();
    aws.clearRequests();
  }

  @AfterEach
  void close() {
    aws.close();
  }

  @Test
  void theKeyringEncryptsAndDecryptsWithAnInMemoryKeyStore() {
    InMemoryKeyStore memory = new InMemoryKeyStore(dynamoDb.getKeyStoreInfo());
    memory.putActive(dynamoDb.getActiveBranchKey(b -> b.branchKeyId(branchKeyId)).branchKeyMaterials());
    aws.clearRequests();
    AwsKmsHierarchicalKeyring keyring = keyring(memory);
    assertSame(memory, keyring.keyStore());

    EncryptionMaterials encrypted = keyring.onEncrypt(OnEncryptRequest.builder().materials(encryptionMaterials()).build()).materials();
    assertTrue(decrypt(keyring, encrypted.encryptedDataKeys()).contentEquals(encrypted.plaintextDataKey().get()));
    assertEquals(0, aws.requests("native").size());
    // The same branch key from DynamoDB decrypts the message: the custom store changes where keys come from, not the format.
    assertTrue(decrypt(keyring(dynamoDb), encrypted.encryptedDataKeys()).contentEquals(encrypted.plaintextDataKey().get()));
    assertTrue(aws.requests("native").size() > 0);
  }

  // The DB-ESDK beacon key source reads beacon keys through the interface too.
  @Test
  void theBeaconKeySourceDerivesTheSameKeysFromAnInMemoryKeyStore() {
    BeaconKeyMaterials fetched = dynamoDb.getBeaconKey(b -> b.branchKeyId(branchKeyId)).beaconKeyMaterials();
    InMemoryKeyStore memory = new InMemoryKeyStore(dynamoDb.getKeyStoreInfo());
    memory.putBeacon(fetched);
    Map<String, SecretBytes> expected = beaconSource(dynamoDb).hmacKeys(branchKeyId);
    aws.clearRequests();
    Map<String, SecretBytes> derived = beaconSource(memory).hmacKeys(branchKeyId);
    assertEquals(0, aws.requests("native").size());
    assertEquals(expected.keySet(), derived.keySet());
    for (Map.Entry<String, SecretBytes> entry : expected.entrySet()) {
      assertTrue(entry.getValue().contentEquals(derived.get(entry.getKey())));
    }
  }

  private BeaconKeySource beaconSource(KeyStore store) {
    return BeaconKeySource.singleKeyStore(store, branchKeyId).beaconNames(Collections.singletonList("b")).cacheTtlSeconds(60).build();
  }

  @Test
  void aKeyStoresExceptionsPassThroughUnchanged() {
    CustomerException failure = new CustomerException();
    KeyStore failing = new Delegating(dynamoDb) {
      @Override
      public GetActiveBranchKeyResponse getActiveBranchKey(GetActiveBranchKeyRequest request) {
        throw failure;
      }

      @Override
      public GetBranchKeyVersionResponse getBranchKeyVersion(GetBranchKeyVersionRequest request) {
        throw failure;
      }
    };
    AwsKmsHierarchicalKeyring keyring = keyring(failing);
    assertSame(failure, assertThrows(CustomerException.class, () -> keyring.onEncrypt(OnEncryptRequest.builder().materials(encryptionMaterials()).build())));
    // On decrypt the keyring collects one failure per encrypted data key, as for any other.
    List<EncryptedDataKey> edks = keyring(dynamoDb).onEncrypt(OnEncryptRequest.builder().materials(encryptionMaterials()).build()).materials().encryptedDataKeys();
    NoMatchingDataKeyException none = assertThrows(NoMatchingDataKeyException.class, () -> decrypt(keyring, edks));
    assertEquals(1, none.failures().size());
    assertSame(failure, none.failures().get(0));

    KeyStore noInfo = new Delegating(dynamoDb) {
      @Override
      public GetKeyStoreInfoResponse getKeyStoreInfo(GetKeyStoreInfoRequest request) {
        throw failure;
      }
    };
    assertSame(failure, assertThrows(CustomerException.class, () -> keyring(noInfo)));
  }

  // The cache identifier binds the logical key store name the store reports, whatever the implementation.
  @Test
  void cacheEntriesAreSharedByTheLogicalNameFromGetKeyStoreInfo() {
    CryptographicMaterialsCache shared = MultiThreadedCache.builder().entryCapacity(10).build();
    AtomicInteger reads = new AtomicInteger();
    Delegating sameName = new Delegating(dynamoDb, reads, dynamoDb.getKeyStoreInfo());
    Delegating otherName = new Delegating(dynamoDb, reads, dynamoDb.getKeyStoreInfo().toBuilder().logicalKeyStoreName("other").build());
    builder(dynamoDb).cache(shared).partitionId("p").build().onEncrypt(OnEncryptRequest.builder().materials(encryptionMaterials()).build());
    builder(sameName).cache(shared).partitionId("p").build().onEncrypt(OnEncryptRequest.builder().materials(encryptionMaterials()).build());
    assertEquals(0, reads.get());
    builder(otherName).cache(shared).partitionId("p").build().onEncrypt(OnEncryptRequest.builder().materials(encryptionMaterials()).build());
    assertEquals(1, reads.get());
  }

  private AwsKmsHierarchicalKeyring.Builder builder(KeyStore store) {
    return AwsKmsHierarchicalKeyring.builder().keyStore(store).branchKeyId(branchKeyId).ttl(Duration.ofSeconds(600));
  }

  private AwsKmsHierarchicalKeyring keyring(KeyStore store) {
    return builder(store).build();
  }

  private static EncryptionMaterials encryptionMaterials() {
    return EncryptionMaterials.builder(EsdkAlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).encryptionContext(EncryptionContext.of("a", "b")).build();
  }

  private static SecretBytes decrypt(AwsKmsHierarchicalKeyring keyring, List<EncryptedDataKey> edks) {
    DecryptionMaterials start = DecryptionMaterials.builder(EsdkAlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).encryptionContext(EncryptionContext.of("a", "b")).build();
    return keyring.onDecrypt(OnDecryptRequest.builder().materials(start).encryptedDataKeys(edks).build()).materials().plaintextDataKey().get();
  }

  private static final class CustomerException extends RuntimeException {

    private static final long serialVersionUID = 1L;
  }

  // Branch keys held in memory, built from decrypted bytes as a store over any other storage would build them.
  private static final class InMemoryKeyStore implements KeyStore {

    private final GetKeyStoreInfoResponse info;
    private final Map<String, BranchKeyMaterials> versions = new ConcurrentHashMap<>();
    private final Map<String, String> activeVersions = new ConcurrentHashMap<>();
    private final Map<String, BeaconKeyMaterials> beaconKeys = new ConcurrentHashMap<>();

    InMemoryKeyStore(GetKeyStoreInfoResponse info) {
      this.info = info;
    }

    void putActive(BranchKeyMaterials decrypted) {
      BranchKeyMaterials copy = BranchKeyMaterials
        .builder()
        .branchKeyId(decrypted.branchKeyId())
        .branchKeyVersion(decrypted.branchKeyVersion())
        .encryptionContext(decrypted.encryptionContext())
        .branchKey(decrypted.branchKey())
        .build();
      versions.put(copy.branchKeyId() + "/" + copy.branchKeyVersion(), copy);
      activeVersions.put(copy.branchKeyId(), copy.branchKeyVersion());
    }

    @Override
    public GetActiveBranchKeyResponse getActiveBranchKey(GetActiveBranchKeyRequest request) {
      String version = activeVersions.get(request.branchKeyId());
      return GetActiveBranchKeyResponse.builder().branchKeyMaterials(find(request.branchKeyId(), version)).build();
    }

    @Override
    public GetBranchKeyVersionResponse getBranchKeyVersion(GetBranchKeyVersionRequest request) {
      return GetBranchKeyVersionResponse.builder().branchKeyMaterials(find(request.branchKeyId(), request.branchKeyVersion())).build();
    }

    void putBeacon(BeaconKeyMaterials decrypted) {
      BeaconKeyMaterials copy = BeaconKeyMaterials
        .builder()
        .beaconKeyIdentifier(decrypted.beaconKeyIdentifier())
        .encryptionContext(decrypted.encryptionContext())
        .beaconKey(decrypted.beaconKey().get())
        .build();
      beaconKeys.put(copy.beaconKeyIdentifier(), copy);
    }

    @Override
    public GetBeaconKeyResponse getBeaconKey(GetBeaconKeyRequest request) {
      BeaconKeyMaterials materials = beaconKeys.get(request.branchKeyId());
      if (materials == null) {
        throw new IllegalArgumentException("No beacon key " + request.branchKeyId());
      }
      return GetBeaconKeyResponse.builder().beaconKeyMaterials(materials).build();
    }

    @Override
    public GetKeyStoreInfoResponse getKeyStoreInfo(GetKeyStoreInfoRequest request) {
      return info;
    }

    private BranchKeyMaterials find(String id, String version) {
      BranchKeyMaterials materials = versions.get(id + "/" + version);
      if (materials == null) {
        throw new IllegalArgumentException("No branch key " + id + " version " + version);
      }
      return materials;
    }
  }

  // Wraps a DynamoDbKeyStore, counting branch key reads, optionally reporting other key store info.
  private static class Delegating implements KeyStore {

    private final KeyStore delegate;
    private final AtomicInteger reads;
    private final GetKeyStoreInfoResponse info;

    Delegating(KeyStore delegate) {
      this(delegate, new AtomicInteger(), delegate.getKeyStoreInfo());
    }

    Delegating(KeyStore delegate, AtomicInteger reads, GetKeyStoreInfoResponse info) {
      this.delegate = delegate;
      this.reads = reads;
      this.info = info;
    }

    @Override
    public GetActiveBranchKeyResponse getActiveBranchKey(GetActiveBranchKeyRequest request) {
      reads.incrementAndGet();
      return delegate.getActiveBranchKey(request);
    }

    @Override
    public GetBranchKeyVersionResponse getBranchKeyVersion(GetBranchKeyVersionRequest request) {
      reads.incrementAndGet();
      return delegate.getBranchKeyVersion(request);
    }

    @Override
    public GetBeaconKeyResponse getBeaconKey(GetBeaconKeyRequest request) {
      return delegate.getBeaconKey(request);
    }

    @Override
    public GetKeyStoreInfoResponse getKeyStoreInfo(GetKeyStoreInfoRequest request) {
      return info;
    }
  }
}
