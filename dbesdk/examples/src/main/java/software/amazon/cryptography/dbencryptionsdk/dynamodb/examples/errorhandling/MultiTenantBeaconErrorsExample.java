package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Map;
import javax.crypto.KeyGenerator;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconKeySource;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.StandardBeacon;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.ValidationException;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * Shows the mistakes that the DB-ESDK rejects on a multi-tenant table, where each tenant has its
 * own beacon key.
 *
 * <p>The DB-ESDK computes each tenant's beacons with that tenant's beacon key, so it rejects a
 * search that does not name the tenant.
 *
 * <p>A multi-tenant table also needs one hierarchical keyring, so that each item has exactly one
 * data key, from the tenant's branch key. The DB-ESDK rejects a write with any other keyring. It
 * also rejects a Query or Scan result item that has more than one data key, for example an item
 * written earlier with a multi keyring.
 *
 * <p>Each case throws {@link ValidationException}.
 *
 * <p>Running this example needs AWS credentials and a key store. Every request below is rejected
 * before it is sent, so the table does not have to exist.
 */
public class MultiTenantBeaconErrorsExample {

  private static final String PARTITION_KEY = "work_id";
  private static final String SORT_KEY = "inspection_date";
  private static final String INSPECTOR_ID_LAST4 = "inspector_id_last4";
  private static final String TENANT_ID = "tenant_id";

  public static void multiTenantBeaconErrors(
    String tableName,
    String keyStoreTableName,
    String branchKeyWrappingKmsKeyArn
  ) {
    try (
      DynamoDbClient keyStoreDynamoDbClient = DynamoDbClient.create();
      KmsClient keyStoreKmsClient = KmsClient.create()
    ) {
      BranchKeyStore keyStore = BranchKeyStore
        .builder()
        .ddbTableName(keyStoreTableName)
        .logicalKeyStoreName(keyStoreTableName)
        .kmsConfiguration(
          KmsConfiguration.kmsKeyArn(branchKeyWrappingKmsKeyArn)
        )
        .ddbClient(keyStoreDynamoDbClient)
        .kmsClient(keyStoreKmsClient)
        .build();

      // A multi-tenant table needs a hierarchical keyring. This Raw AES keyring is the mistake that
      // the write case below shows.
      Keyring rawAesKeyring = RawAesKeyring
        .builder()
        .keyName("my-aes-key-name")
        .keyNamespace("my-key-namespace")
        .wrappingKey(SecretBytes.copyOf(generateAesKeyBytes()))
        .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
        .build();

      ItemEncryptionSchema schema = ItemEncryptionSchema
        .builder()
        .partitionKeyName(PARTITION_KEY)
        .sortKeyName(SORT_KEY)
        .signOnly(TENANT_ID)
        .encryptAndSign(INSPECTOR_ID_LAST4)
        .build();
      StandardBeacon last4Beacon = StandardBeacon
        .builder()
        .name(INSPECTOR_ID_LAST4)
        .bitLength(10)
        .build();
      // Each item's tenant_id attribute holds the ID of that tenant's beacon key.
      BeaconKeySource beaconKeySource = BeaconKeySource
        .multipleBeaconKeys(TENANT_ID)
        .cacheTtl(Duration.ofMinutes(10))
        .build();
      BeaconConfig beaconConfig = BeaconConfig
        .builder()
        .standardBeacons(last4Beacon)
        .keyStore(keyStore)
        .keySource(beaconKeySource)
        .build();
      DynamoDbTableEncryptionConfig tableConfig = DynamoDbTableEncryptionConfig
        .builder()
        .tableName(tableName)
        .schema(schema)
        .keyring(rawAesKeyring)
        .beaconConfig(beaconConfig)
        .build();
      DynamoDbEncryptionInterceptor encryptionInterceptor =
        DynamoDbEncryptionInterceptor
          .builder()
          .tableConfigs(tableConfig)
          .build();

      try (
        DynamoDbClient dynamoDbClient = DynamoDbClient
          .builder()
          .overrideConfiguration(overrides ->
            overrides.addExecutionInterceptor(encryptionInterceptor)
          )
          .build()
      ) {
        multiTenantSearchWithoutTenant(dynamoDbClient, tableName);
        multiTenantWriteWithoutHierarchicalKeyring(dynamoDbClient, tableName);
      }
    }
  }

  // The filter has no tenant_id condition, so the DB-ESDK cannot tell which tenant's beacon key to
  // use.
  private static void multiTenantSearchWithoutTenant(
    DynamoDbClient dynamoDbClient,
    String tableName
  ) {
    ScanRequest request = ScanRequest
      .builder()
      .tableName(tableName)
      .filterExpression(INSPECTOR_ID_LAST4 + " = :last4")
      .expressionAttributeValues(Map.of(":last4", AttributeValue.fromS("4321")))
      .build();
    try {
      dynamoDbClient.scan(request);
    } catch (ValidationException exception) {
      System.err.println(
        "Add the tenant to the search, for example " +
        TENANT_ID +
        " = :tenant: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "A multi-tenant search that names no tenant was sent"
    );
  }

  private static void multiTenantWriteWithoutHierarchicalKeyring(
    DynamoDbClient dynamoDbClient,
    String tableName
  ) {
    PutItemRequest request = PutItemRequest
      .builder()
      .tableName(tableName)
      .item(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS("MultiTenantBeaconErrorsExample"),
          SORT_KEY,
          AttributeValue.fromS("2026-11-17"),
          TENANT_ID,
          AttributeValue.fromS("tenant1"),
          INSPECTOR_ID_LAST4,
          AttributeValue.fromS("4321")
        )
      )
      .build();
    try {
      dynamoDbClient.putItem(request);
    } catch (ValidationException exception) {
      System.err.println(
        "Use one hierarchical keyring for a multi-tenant table: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "A multi-tenant write with a Raw AES keyring was accepted"
    );
  }

  public static void main(String[] args) {
    if (args.length < 3) {
      throw new IllegalArgumentException(
        "To run this example, include the tableName, keyStoreTableName and " +
        "branchKeyWrappingKmsKeyArn in args"
      );
    }
    multiTenantBeaconErrors(args[0], args[1], args[2]);
  }

  private static byte[] generateAesKeyBytes() {
    // This example uses the JCA KeyGenerator to generate the key bytes. In practice, do not
    // generate this key in your code; get it from a key management system, such as an HSM.
    KeyGenerator aesKeyGenerator;
    try {
      aesKeyGenerator = KeyGenerator.getInstance("AES");
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException(
        "This JVM does not support AES key generation",
        exception
      );
    }
    aesKeyGenerator.init(256, new SecureRandom());
    return aesKeyGenerator.generateKey().getEncoded();
  }
}
