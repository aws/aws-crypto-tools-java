// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.SecretBytes;
import software.amazon.cryptography.mpl.examples.dbesdk.ClientSupplierExample;
import software.amazon.cryptography.mpl.examples.dbesdk.KmsEcdhKeyringExample;
import software.amazon.cryptography.mpl.examples.dbesdk.KmsRsaKeyringExample;
import software.amazon.cryptography.mpl.examples.dbesdk.MrkDiscoveryMultiKeyringExample;
import software.amazon.cryptography.mpl.examples.dbesdk.MrkMultiKeyringExample;
import software.amazon.cryptography.mpl.examples.dbesdk.MultiKeyringExample;
import software.amazon.cryptography.mpl.examples.dbesdk.RequiredEncryptionContextExample;
import software.amazon.cryptography.mpl.examples.dbesdk.SearchableEncryptionExample;
import software.amazon.cryptography.mpl.examples.esdk.AwsKmsRsaKeyringExample;
import software.amazon.cryptography.mpl.examples.esdk.CommitmentPolicyAndAlgorithmExample;
import software.amazon.cryptography.mpl.examples.esdk.CustomClientSupplierExample;
import software.amazon.cryptography.mpl.examples.esdk.CustomCmmExample;
import software.amazon.cryptography.mpl.examples.esdk.DiscoveryKeyringExample;
import software.amazon.cryptography.mpl.examples.esdk.ErrorHandlingExample;
import software.amazon.cryptography.mpl.examples.esdk.ErrorHandlingExample.Outcome;
import software.amazon.cryptography.mpl.examples.esdk.EscrowMultiKeyringExample;
import software.amazon.cryptography.mpl.examples.esdk.EsdkLikeClient;
import software.amazon.cryptography.mpl.examples.esdk.HierarchicalKeyringExample;
import software.amazon.cryptography.mpl.examples.esdk.KmsKeyringExample;
import software.amazon.cryptography.mpl.examples.esdk.KmsMultiKeyringExample;
import software.amazon.cryptography.mpl.examples.esdk.MrkDiscoveryKeyringExample;
import software.amazon.cryptography.mpl.examples.esdk.RequiredEncryptionContextCmmExample;
import software.amazon.cryptography.mpl.examples.esdk.SharedCacheExample;
import software.amazon.cryptography.mpl.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.mpl.keyrings.AwsKmsKeyring;
import software.amazon.cryptography.mpl.keyrings.ClientSupplier;
import software.amazon.cryptography.mpl.keystore.BranchKeyStore;
import software.amazon.cryptography.mpl.keystore.KmsConfiguration;

// The ESDK and DB-ESDK examples that need AWS, run on the native MPL against the real keys and the key store table.
// The examples check their own results and throw on a mismatch.
class RealExamplesIT {

  private static RealAws aws;
  private static KmsClient kms;
  private static DynamoDbClient ddb;
  // The multi keyrings close what they own, so each example gets new clients.
  private static ClientSupplier clients;

  @BeforeAll
  static void clients() {
    aws = RealAws.fromEnvironment();
    kms = aws.newKms(aws.region);
    ddb = aws.dynamoDb(aws.region);
    clients = region -> aws.newKms(region);
  }

  @AfterAll
  static void close() {
    aws.close();
  }

  @Test
  void esdkKmsExamples() throws Exception {
    KmsKeyringExample.encryptAndDecrypt(aws.sym, kms);
    KmsMultiKeyringExample.encryptAndDecrypt(aws.sym, aws.mrkReplica, clients);
    DiscoveryKeyringExample.encryptAndDecrypt(aws.sym, aws.region, "aws", aws.account, kms, clients);
    MrkDiscoveryKeyringExample.encryptAndDecrypt(aws.mrk, aws.replicaRegion, "aws", aws.account, clients);
    EscrowMultiKeyringExample.encryptAndDecrypt(aws.sym, kms);
    String pem = "-----BEGIN PUBLIC KEY-----\n" +
      Base64.getMimeEncoder().encodeToString(kms.getPublicKey(r -> r.keyId(aws.rsa)).publicKey().asByteArray()) +
      "\n-----END PUBLIC KEY-----\n";
    AwsKmsRsaKeyringExample.encryptAndDecrypt(aws.rsa, pem.getBytes(StandardCharsets.US_ASCII), kms);
    RequiredEncryptionContextCmmExample.encryptAndDecrypt(aws.sym, kms);
    CommitmentPolicyAndAlgorithmExample.encryptAndDecrypt(aws.sym, kms);
    CustomCmmExample.encryptAndDecrypt(aws.sym, kms);
    Map<String, KmsClient> built = CustomClientSupplierExample.encryptAndDecrypt(aws.sym, aws::newKms);
    assertEquals(Collections.singleton(aws.region), built.keySet());
  }

  @Test
  void esdkKeyStoreExamples() {
    HierarchicalKeyringExample.encryptAndDecrypt(RealAws.TABLE, RealAws.LOGICAL_NAME, aws.sym, kms, ddb);
    try (BranchKeyStore store = store()) {
      String branchKey = store.createKey();
      System.out.println("created branch key " + branchKey);
      SharedCacheExample.encryptAndDecrypt(RealAws.TABLE, RealAws.LOGICAL_NAME, "partition", aws.sym, branchKey, kms, ddb);
    }
  }

  // The real-service failures the error-handling example classifies.
  @Test
  void errorHandlingClassifiesRealFailures() {
    Map<String, String> context = Collections.singletonMap("k", "v");
    Keyring keyring = AwsKmsKeyring.builder().kmsKeyId(aws.sym).kmsClient(kms).build();
    EsdkLikeClient crypto = EsdkLikeClient.builder().build();
    byte[] ciphertext = crypto.encryptData(keyring, "data".getBytes(StandardCharsets.UTF_8), context);
    assertEquals(Outcome.DECRYPTED, ErrorHandlingExample.decrypt(crypto, keyring, ciphertext, context));
    Keyring otherKey = AwsKmsKeyring.builder().kmsKeyId(aws.mrk).kmsClient(kms).build();
    assertEquals(Outcome.NOT_FOR_THIS_KEYRING, ErrorHandlingExample.decrypt(crypto, otherKey, ciphertext, context));
    assertEquals(Outcome.INVALID_REQUEST, ErrorHandlingExample.decrypt(crypto, keyring, ciphertext, Collections.singletonMap("k", "other")));
    // KMS answers a Decrypt of a single-Region key's ciphertext in another Region with AccessDeniedException.
    Keyring otherRegion = AwsKmsKeyring.builder().kmsKeyId(aws.sym).kmsClient(aws.newKms(aws.replicaRegion)).build();
    assertEquals(Outcome.ACCESS_DENIED, ErrorHandlingExample.decrypt(crypto, otherRegion, ciphertext, context));
  }

  @Test
  void dbEsdkKmsExamples() throws Exception {
    Map<String, String> encrypted = MrkMultiKeyringExample.encryptAndDecryptInAnotherRegion(aws.mrk, aws.mrkReplica, clients);
    Map<String, String> decrypted = MrkDiscoveryMultiKeyringExample.decrypt(encrypted, aws.replicaRegion, Collections.singletonList(aws.account), clients);
    assertEquals("encrypt and sign me!", decrypted.get("sensitive_data"));
    List<Throwable> failures = MrkDiscoveryMultiKeyringExample.whyDecryptFailed(
      encrypted,
      aws.replicaRegion,
      Collections.singletonList(RealAws.OTHER_ACCOUNT),
      clients
    );
    assertEquals(1, failures.size());
    assertTrue(failures.get(0) instanceof NoMatchingDataKeyException, String.valueOf(failures.get(0)));
    KmsEcdhKeyringExample.encryptAndDecrypt(kms, aws.ecc, aws.ecc);
    KmsRsaKeyringExample.encryptAndDecrypt(kms, aws.rsa);
    MultiKeyringExample.encryptAndDecryptWithEitherKey(kms, aws.sym, SecretBytes.random(32));
    Map<String, String> roles = new HashMap<>();
    roles.put(aws.region, "west");
    roles.put(aws.replicaRegion, "east");
    ClientSupplierExample.encryptAndDecrypt(
      aws.mrk,
      aws.replicaRegion,
      aws.account,
      new ClientSupplierExample.RegionalRoleClientSupplier(roles, (role, region) -> aws.newKms(region))
    );
  }

  @Test
  void dbEsdkKeyStoreExamples() {
    List<Map<String, String>> tenants = software.amazon.cryptography.mpl.examples.dbesdk.HierarchicalKeyringExample.encryptAndDecryptForTwoTenants(
      ddb,
      kms,
      RealAws.TABLE,
      RealAws.LOGICAL_NAME,
      aws.sym
    );
    assertEquals(2, tenants.size());
    try (BranchKeyStore store = store()) {
      String first = store.createKey();
      System.out.println("created branch key " + first);
      String beacon = SearchableEncryptionExample.singleKeyStoreBeacon(store, first, "4321");
      assertEquals(beacon, SearchableEncryptionExample.singleKeyStoreBeacon(store, first, "4321"));
      String second = store.createKey();
      System.out.println("created branch key " + second);
      Map<String, String> perTenant = SearchableEncryptionExample.multiKeyStoreBeacons(store, first, second, "4321");
      assertEquals(beacon, perTenant.get(first));
      assertEquals(3, perTenant.get(second).length());
      RequiredEncryptionContextExample.encryptAndDecrypt(store);
      assertTrue(RequiredEncryptionContextExample.decryptAfterChangingSortKey(store) instanceof NoMatchingDataKeyException);
      assertEquals(3, software.amazon.cryptography.mpl.examples.dbesdk.SharedCacheExample.shareOneCache(store, first).length());
    }
  }

  private static BranchKeyStore store() {
    return BranchKeyStore
      .builder()
      .ddbTableName(RealAws.TABLE)
      .logicalKeyStoreName(RealAws.LOGICAL_NAME)
      .kmsConfiguration(KmsConfiguration.kmsKeyArn(aws.sym))
      .kmsClient(kms)
      .ddbClient(ddb)
      .build();
  }
}
