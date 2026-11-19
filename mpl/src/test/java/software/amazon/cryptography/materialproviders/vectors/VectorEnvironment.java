// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.vectors;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.keystore.DynamoDbKeyStore;
import software.amazon.cryptography.materialproviders.keystore.KmsConfiguration;

/**
 * The keys of a keys manifest, and an in-process AWS that serves the ones that live in AWS:
 * <ul>
 *   <li>each {@code aws-kms} key is a fake KMS symmetric key with the manifest's ARN; {@code mrk-} ARNs that differ
 *       only by Region are replicas of one key. KMS key material is never visible to a caller, so this is faithful;</li>
 *   <li>each {@code static-branch-key} is written to a fake key store table, wrapped by a fake KMS key, so a key store
 *       returns exactly the branch key, version, and id the Dafny runner's static key store returns.</li>
 * </ul>
 * The {@code aws-kms-rsa} and {@code aws-kms-ecdh} keys are not served: their manifests carry public keys whose
 * private halves exist only in real KMS.
 */
final class VectorEnvironment implements AutoCloseable {

  static final String KEY_STORE_REGION = "us-west-2";
  static final String KEY_STORE_TABLE = "KeyStoreTable";
  /** The logical name the Dafny runner's static key store reports. */
  static final String LOGICAL_KEY_STORE_NAME = "logical-key-store-name";
  private static final String CREATE_TIME = "2023-04-18T00:00:00.000000Z";

  final FakeAws aws = FakeAws.start();
  final Map<String, KeyMaterial> keys;
  final String keyStoreKmsKey;
  private final Map<String, KmsClient> kmsClients = new HashMap<>();

  VectorEnvironment(Map<String, KeyMaterial> keys) {
    this.keys = keys;
    importKmsKeys();
    keyStoreKmsKey = aws.kms().createSymmetricKey(KEY_STORE_REGION);
    seedBranchKeys();
  }

  synchronized KmsClient kms(String region) {
    return kmsClients.computeIfAbsent(region, r -> aws.kmsClient("native", r));
  }

  DynamoDbClient dynamoDb() {
    return aws.dynamoDbClient("native", KEY_STORE_REGION);
  }

  DynamoDbKeyStore keyStore() {
    return DynamoDbKeyStore
      .builder()
      .ddbTableName(KEY_STORE_TABLE)
      .kmsConfiguration(KmsConfiguration.kmsKeyArn(keyStoreKmsKey))
      .logicalKeyStoreName(LOGICAL_KEY_STORE_NAME)
      .ddbClient(dynamoDb())
      .kmsClient(kms(KEY_STORE_REGION))
      .build();
  }

  /** The Region of a KMS key ARN, as getKmsClient reads it; empty for anything else. */
  static String region(String keyArn) {
    String[] parts = keyArn.split(":", 6);
    return parts.length == 6 && parts[0].equals("arn") && parts[2].equals("kms") ? parts[3] : "";
  }

  private void importKmsKeys() {
    Map<String, List<String>> byKeyId = new LinkedHashMap<>();
    for (KeyMaterial material : keys.values()) {
      if (material instanceof KeyMaterial.Kms) {
        String arn = ((KeyMaterial.Kms) material).keyIdentifier;
        String resource = arn.split(":", 6)[5];
        String id = resource.startsWith("key/mrk-") ? resource : arn;
        List<String> arns = byKeyId.computeIfAbsent(id, k -> new ArrayList<>());
        if (!arns.contains(arn)) {
          arns.add(arn);
        }
      }
    }
    for (List<String> arns : byKeyId.values()) {
      aws.kms().createSymmetricKeys(arns.toArray(new String[0]));
    }
  }

  // The items CreateKey would write (Structure.dfy), with the manifest's branch key instead of a generated one.
  private void seedBranchKeys() {
    try (DynamoDbKeyStore store = keyStore()) {
      store.createKeyStore();
    }
    for (KeyMaterial material : keys.values()) {
      if (!(material instanceof KeyMaterial.StaticBranchKey)) {
        continue;
      }
      KeyMaterial.StaticBranchKey branchKey = (KeyMaterial.StaticBranchKey) material;
      Map<String, String> version = new LinkedHashMap<>();
      version.put("branch-key-id", branchKey.keyIdentifier);
      version.put("type", "branch:version:" + branchKey.branchKeyVersion);
      version.put("create-time", CREATE_TIME);
      version.put("kms-arn", keyStoreKmsKey);
      version.put("hierarchy-version", "1");
      Map<String, String> active = new LinkedHashMap<>(version);
      active.put("type", "branch:ACTIVE");
      active.put("version", "branch:version:" + branchKey.branchKeyVersion);
      putItem(version, branchKey.branchKey);
      putItem(active, branchKey.branchKey);
    }
  }

  private void putItem(Map<String, String> attributes, byte[] branchKey) {
    Map<String, String> context = new HashMap<>(attributes);
    context.put("tablename", LOGICAL_KEY_STORE_NAME);
    byte[] wrapped = kms(KEY_STORE_REGION)
      .encrypt(r -> r.keyId(keyStoreKmsKey).plaintext(SdkBytes.fromByteArray(branchKey)).encryptionContext(context))
      .ciphertextBlob()
      .asByteArray();
    Map<String, AttributeValue> item = new HashMap<>();
    for (Map.Entry<String, String> attribute : attributes.entrySet()) {
      item.put(
        attribute.getKey(),
        attribute.getKey().equals("hierarchy-version")
          ? AttributeValue.builder().n(attribute.getValue()).build()
          : AttributeValue.builder().s(attribute.getValue()).build()
      );
    }
    item.put("enc", AttributeValue.builder().b(SdkBytes.fromByteArray(wrapped)).build());
    dynamoDb().putItem(r -> r.tableName(KEY_STORE_TABLE).item(item));
  }

  @Override
  public void close() {
    aws.close();
  }
}
