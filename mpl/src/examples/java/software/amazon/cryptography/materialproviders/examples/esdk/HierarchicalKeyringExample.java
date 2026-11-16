// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.esdk.EsdkNoMatchingDataKeyException;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.cache.CacheType;
import software.amazon.cryptography.materialproviders.exceptions.ResourceNotFoundException;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;
import software.amazon.cryptography.materialproviders.keyrings.BranchKeyIdSupplier;
import software.amazon.cryptography.materialproviders.keyrings.GetBranchKeyIdRequest;
import software.amazon.cryptography.materialproviders.keyrings.GetBranchKeyIdResponse;

/**
 * Encrypts messages for two tenants with a hierarchical keyring. A branch key id supplier picks each tenant's branch
 * key from the encryption context, and the keyring caches branch keys so most messages need no KMS call.
 *
 * <p>Creates the key store table if it does not exist, a branch key per tenant, and a new version of one of them.
 *
 * <p>Arguments: the key store's table name, its logical name, and the ARN of the KMS key that protects its branch
 * keys, in the SDK's default Region. The KMS key needs GenerateDataKeyWithoutPlaintext, ReEncrypt, and Decrypt.
 */
public final class HierarchicalKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private HierarchicalKeyringExample() {}

  public static void main(String[] args) {
    if (args.length != 3) {
      throw new IllegalArgumentException("Arguments: <key-store-table> <logical-key-store-name> <kms-key-arn>");
    }
    try (KmsClient kmsClient = KmsClient.create(); DynamoDbClient ddbClient = DynamoDbClient.create()) {
      run(args[0], args[1], args[2], kmsClient, ddbClient);
    }
  }

  public static void run(
    String keyStoreTableName,
    String logicalKeyStoreName,
    String kmsKeyArn,
    KmsClient kmsClient,
    DynamoDbClient ddbClient
  ) {
    // 1. Instantiate the ESDK.
    EsdkClient esdk = EsdkClient.create();

    // 2. Configure the key store.
    // Always use the same logical name for a table: it is bound into every branch key.
    // Closing the key store closes only the clients it created, not these.
    try (
      BranchKeyStore keyStore = BranchKeyStore
        .builder()
        .ddbTableName(keyStoreTableName)
        .logicalKeyStoreName(logicalKeyStoreName)
        .kmsConfiguration(KmsConfiguration.kmsKeyArn(kmsKeyArn))
        .kmsClient(kmsClient)
        .ddbClient(ddbClient)
        .build()
    ) {
      // 3. Create the table and a branch key per tenant; an operator usually does this once.
      // createKeyStore does not wait for a new table, and creating keys fails until the table is active.
      keyStore.createKeyStore();
      ddbClient.waiter().waitUntilTableExists(b -> b.tableName(keyStoreTableName));
      String branchKeyIdA = keyStore.createKey().branchKeyIdentifier();
      String branchKeyIdB = keyStore.createKey().branchKeyIdentifier();
      String versionA = awaitNewActiveVersion(keyStore, branchKeyIdA, null);
      awaitNewActiveVersion(keyStore, branchKeyIdB, null);

      // 4. Create the hierarchical keyring.
      // The TTL bounds how long a cached branch key is used before the keyring asks KMS again.
      Keyring keyring = AwsKmsHierarchicalKeyring
        .builder()
        .keyStore(keyStore)
        .branchKeyIdSupplier(new TenantBranchKeyIdSupplier(branchKeyIdA, branchKeyIdB))
        .ttl(Duration.ofMinutes(10))
        .cache(CacheType.defaultCache(100))
        .build();

      // 5. Encrypt a message for each tenant.
      Map<String, String> encryptionContextA = encryptionContext("TenantA");
      Map<String, String> encryptionContextB = encryptionContext("TenantB");
      byte[] ciphertextA = esdk
        .encrypt(b -> b.plaintext(EXAMPLE_DATA).keyring(keyring).encryptionContext(encryptionContextA))
        .ciphertext();
      byte[] ciphertextB = esdk
        .encrypt(b -> b.plaintext(EXAMPLE_DATA).keyring(keyring).encryptionContext(encryptionContextB))
        .ciphertext();

      // 6. A keyring with only tenant B's branch key cannot decrypt tenant A's message.
      Keyring tenantBKeyring = AwsKmsHierarchicalKeyring
        .builder()
        .keyStore(keyStore)
        .branchKeyId(branchKeyIdB)
        .ttl(Duration.ofMinutes(10))
        .build();
      try {
        esdk.decrypt(b -> b.ciphertext(ciphertextA).keyring(tenantBKeyring));
        throw new IllegalStateException("Tenant B's keyring decrypted tenant A's message");
      } catch (EsdkNoMatchingDataKeyException expected) {
        // The message's only encrypted data key is for tenant A's branch key.
      }

      // 7. Decrypt both messages with the keyring that encrypted them.
      requireExampleData(esdk.decrypt(b -> b.ciphertext(ciphertextA).keyring(keyring)).plaintext());
      requireExampleData(esdk.decrypt(b -> b.ciphertext(ciphertextB).keyring(tenantBKeyring)).plaintext());

      // 8. Rotate tenant A's branch key; messages from before and after the rotation decrypt.
      // A keyring encrypts with the new version once its cached copy expires; this one caches nothing.
      keyStore.versionKey(b -> b.branchKeyIdentifier(branchKeyIdA));
      awaitNewActiveVersion(keyStore, branchKeyIdA, versionA);
      Keyring uncachedKeyring = AwsKmsHierarchicalKeyring
        .builder()
        .keyStore(keyStore)
        .branchKeyIdSupplier(new TenantBranchKeyIdSupplier(branchKeyIdA, branchKeyIdB))
        .ttl(Duration.ofMinutes(10))
        .cache(CacheType.noCache())
        .build();
      byte[] afterRotation = esdk
        .encrypt(b -> b.plaintext(EXAMPLE_DATA).keyring(uncachedKeyring).encryptionContext(encryptionContextA))
        .ciphertext();
      requireExampleData(esdk.decrypt(b -> b.ciphertext(afterRotation).keyring(keyring)).plaintext());
      requireExampleData(esdk.decrypt(b -> b.ciphertext(ciphertextA).keyring(uncachedKeyring)).plaintext());
    }
  }

  private static Map<String, String> encryptionContext(String tenant) {
    Map<String, String> encryptionContext = new HashMap<>();
    encryptionContext.put("tenant", tenant);
    encryptionContext.put("encryption", "context");
    return encryptionContext;
  }

  // Key store reads are eventually consistent, so a branch key just created or rotated can take a moment to read.
  private static String awaitNewActiveVersion(BranchKeyStore keyStore, String branchKeyId, String previousVersion) {
    for (int attempt = 0; attempt < 20; attempt++) {
      try {
        String version = keyStore
          .getActiveBranchKey(b -> b.branchKeyIdentifier(branchKeyId))
          .branchKeyMaterials()
          .branchKeyVersion();
        if (!version.equals(previousVersion)) {
          return version;
        }
      } catch (ResourceNotFoundException notYetReadable) {
        // Try again below.
      }
      try {
        Thread.sleep(250);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new IllegalStateException("Interrupted while waiting for branch key " + branchKeyId, e);
      }
    }
    throw new IllegalStateException("No new active version of branch key " + branchKeyId);
  }

  private static void requireExampleData(byte[] plaintext) {
    if (!Arrays.equals(plaintext, EXAMPLE_DATA)) {
      throw new IllegalStateException("Decrypted plaintext does not match");
    }
  }

  /** Maps the encryption context's "tenant" entry to that tenant's branch key. */
  static final class TenantBranchKeyIdSupplier implements BranchKeyIdSupplier {

    private final String branchKeyIdA;
    private final String branchKeyIdB;

    TenantBranchKeyIdSupplier(String branchKeyIdA, String branchKeyIdB) {
      this.branchKeyIdA = branchKeyIdA;
      this.branchKeyIdB = branchKeyIdB;
    }

    @Override
    public GetBranchKeyIdResponse getBranchKeyId(GetBranchKeyIdRequest request) {
      String tenant = request.encryptionContext().get("tenant");
      String branchKeyId;
      if ("TenantA".equals(tenant)) {
        branchKeyId = branchKeyIdA;
      } else if ("TenantB".equals(tenant)) {
        branchKeyId = branchKeyIdB;
      } else {
        // Failing here fails the encrypt or decrypt call, before any key store call.
        throw new IllegalArgumentException("Encryption context has no known tenant");
      }
      return GetBranchKeyIdResponse.builder().branchKeyId(branchKeyId).build();
    }
  }
}
