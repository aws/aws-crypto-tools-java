// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.dbesdk;

import java.util.HashMap;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.materialproviders.DbeAlgorithmSuite;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsEcdhKeyring;
import software.amazon.cryptography.materialproviders.keyrings.EcdhCurveSpec;
import software.amazon.cryptography.materialproviders.keyrings.KmsEcdhKeyAgreementScheme;

/**
 * Writes an item with a KMS ECDH keyring, which wraps the data key with a key derived from the sender's KMS key and
 * the recipient's public key; the recipient then reads it with a discovery keyring for its own KMS key.
 *
 * <p>Arguments: a table whose partition key is {@code partition_key} (string) and sort key is {@code sort_key}
 * (number), and the ARNs of two ECC_NIST_P256 KMS keys with key usage KEY_AGREEMENT, the sender's and the recipient's,
 * in the SDK's default Region. Calls KMS GetPublicKey and DeriveSharedSecret, and DynamoDB.
 */
public final class KmsEcdhKeyringExample {

  private KmsEcdhKeyringExample() {}

  public static void main(String[] args) {
    if (args.length != 3) {
      throw new IllegalArgumentException("Arguments: <table-name> <sender-kms-key-arn> <recipient-kms-key-arn>");
    }
    try (KmsClient kmsClient = KmsClient.create()) {
      run(args[0], args[1], args[2], kmsClient);
    }
  }

  public static void run(String tableName, String senderKeyArn, String recipientKeyArn, KmsClient kmsClient) {
    // 1. Get the recipient's public key. A real sender is given it once, and needs no access to the recipient's key.
    byte[] recipientPublicKey = kmsClient.getPublicKey(b -> b.keyId(recipientKeyArn)).publicKey().asByteArray();

    // 2. The sender's keyring. Building it calls GetPublicKey for the sender's key.
    Keyring senderKeyring = AwsKmsEcdhKeyring
      .builder()
      .keyAgreementScheme(KmsEcdhKeyAgreementScheme.kmsPrivateKeyToStaticPublicKey(senderKeyArn, recipientPublicKey))
      .curveSpec(EcdhCurveSpec.ECC_NIST_P256)
      .kmsClient(kmsClient)
      .build();

    // 3. The recipient's keyring: it decrypts any item addressed to its key, from any sender, and encrypts nothing.
    Keyring recipientKeyring = AwsKmsEcdhKeyring
      .builder()
      .keyAgreementScheme(KmsEcdhKeyAgreementScheme.kmsPublicKeyDiscovery(recipientKeyArn))
      .curveSpec(EcdhCurveSpec.ECC_NIST_P256)
      .kmsClient(kmsClient)
      .build();

    // 4. Put and get the item as the sender; the sender's keyring can read what it wrote.
    Map<String, AttributeValue> item = key();
    item.put("sensitive_data", AttributeValue.builder().s("encrypt and sign me!").build());
    try (DynamoDbClient senderClient = encryptingClient(tableName, senderKeyring)) {
      senderClient.putItem(b -> b.tableName(tableName).item(item));
      requireItem(senderClient, tableName);
    }

    // 5. Get the item as the recipient.
    try (DynamoDbClient recipientClient = encryptingClient(tableName, recipientKeyring)) {
      requireItem(recipientClient, tableName);
    }
  }

  // A DynamoDB client that encrypts and decrypts the table's items with the keyring.
  private static DynamoDbClient encryptingClient(String tableName, Keyring keyring) {
    ItemEncryptionSchema schema = ItemEncryptionSchema
      .builder()
      .partitionKeyName("partition_key")
      .sortKeyName("sort_key")
      .encryptAndSign("sensitive_data")
      .build();
    DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .logicalTableName(tableName)
      .schema(schema)
      .keyring(keyring)
      // A suite without an asymmetric signature, as the DB-ESDK's own ECDH examples use.
      .algorithmSuite(DbeAlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384)
      .build();
    DynamoDbEncryptionInterceptor interceptor = DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();
    return DynamoDbClient.builder().overrideConfiguration(o -> o.addExecutionInterceptor(interceptor)).build();
  }

  private static void requireItem(DynamoDbClient ddbClient, String tableName) {
    Map<String, AttributeValue> returned = ddbClient
      .getItem(b -> b.tableName(tableName).key(key()).consistentRead(true))
      .item();
    if (!"encrypt and sign me!".equals(returned.get("sensitive_data").s())) {
      throw new IllegalStateException("The item did not decrypt to what was put");
    }
  }

  private static Map<String, AttributeValue> key() {
    Map<String, AttributeValue> key = new HashMap<>();
    key.put("partition_key", AttributeValue.builder().s("KmsEcdhKeyringExample").build());
    key.put("sort_key", AttributeValue.builder().n("0").build());
    return key;
  }
}
