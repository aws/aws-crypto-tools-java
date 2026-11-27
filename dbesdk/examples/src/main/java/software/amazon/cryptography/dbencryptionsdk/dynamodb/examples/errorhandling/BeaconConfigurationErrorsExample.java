package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling;

import java.time.Duration;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconKeySource;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.StandardBeacon;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.InvalidConfigurationException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.ValidationException;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;

/**
 * Shows the searchable encryption (beacon) configuration mistakes that the DB-ESDK rejects.
 *
 * <p>A beacon lets you search an encrypted attribute: the DB-ESDK writes a short hash of the value
 * next to it, and rewrites your query to compare hashes.
 *
 * <p>The DB-ESDK checks a beacon configuration when you build the interceptor, and throws {@link
 * InvalidConfigurationException} for one it cannot use. The cases below are a beacon on an
 * attribute that is not encrypted, and a beacon key cache time to live under one second. Other
 * settings that it rejects include duplicate beacon or part names, a compound beacon part that is
 * not configured, and a number of partitions above the configured maximum. Do not retry: fix the
 * configuration.
 *
 * <p>{@link InvalidConfigurationException} is a {@link ValidationException}, so a {@code catch} of
 * {@link ValidationException} also catches it.
 *
 * <p>Running this example needs AWS credentials, a key store, and a branch key in it to use as the
 * beacon key.
 */
public class BeaconConfigurationErrorsExample {

  private static final String PARTITION_KEY = "work_id";
  private static final String SORT_KEY = "inspection_date";
  private static final String INSPECTOR_ID_LAST4 = "inspector_id_last4";

  public static void buildInvalidBeaconConfigurations(
    String tableName,
    String branchKeyId,
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
      Keyring hierarchicalKeyring = AwsKmsHierarchicalKeyring
        .builder()
        .branchKeyId(branchKeyId)
        .keyStore(keyStore)
        .ttl(Duration.ofMinutes(10))
        .build();

      buildBeaconOnAttributeThatIsNotEncrypted(
        tableName,
        branchKeyId,
        keyStore,
        hierarchicalKeyring
      );
      buildBeaconKeyCacheWithTimeToLiveTooShort(
        tableName,
        branchKeyId,
        keyStore,
        hierarchicalKeyring
      );
    }
  }

  // A beacon is needed, and allowed, only on an encrypted attribute. Here inspector_id_last4 is
  // signed but not encrypted, so its plaintext value is stored and can be searched directly.
  private static void buildBeaconOnAttributeThatIsNotEncrypted(
    String tableName,
    String branchKeyId,
    BranchKeyStore keyStore,
    Keyring keyring
  ) {
    try {
      ItemEncryptionSchema schemaWithSignedLast4 = ItemEncryptionSchema
        .builder()
        .partitionKeyName(PARTITION_KEY)
        .sortKeyName(SORT_KEY)
        .signOnly(INSPECTOR_ID_LAST4)
        .build();
      StandardBeacon last4Beacon = StandardBeacon
        .builder()
        .name(INSPECTOR_ID_LAST4)
        .bitLength(10)
        .build();
      BeaconKeySource beaconKeySource = BeaconKeySource
        .singleBeaconKey(branchKeyId)
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
        .schema(schemaWithSignedLast4)
        .keyring(keyring)
        .beaconConfig(beaconConfig)
        .build();
      DynamoDbEncryptionInterceptor.builder().tableConfigs(tableConfig).build();
    } catch (InvalidConfigurationException exception) {
      System.err.println(
        "Put beacons only on encrypted attributes: " + exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "A beacon on an attribute that is not encrypted was accepted"
    );
  }

  // The beacon key cache must keep each beacon key for at least one second. Here the time to live
  // is zero.
  private static void buildBeaconKeyCacheWithTimeToLiveTooShort(
    String tableName,
    String branchKeyId,
    BranchKeyStore keyStore,
    Keyring keyring
  ) {
    try {
      ItemEncryptionSchema schemaWithEncryptedLast4 = ItemEncryptionSchema
        .builder()
        .partitionKeyName(PARTITION_KEY)
        .sortKeyName(SORT_KEY)
        .encryptAndSign(INSPECTOR_ID_LAST4)
        .build();
      StandardBeacon last4Beacon = StandardBeacon
        .builder()
        .name(INSPECTOR_ID_LAST4)
        .bitLength(10)
        .build();
      BeaconKeySource beaconKeySourceWithZeroTtl = BeaconKeySource
        .singleBeaconKey(branchKeyId)
        .cacheTtl(Duration.ZERO)
        .build();
      BeaconConfig beaconConfig = BeaconConfig
        .builder()
        .standardBeacons(last4Beacon)
        .keyStore(keyStore)
        .keySource(beaconKeySourceWithZeroTtl)
        .build();
      DynamoDbTableEncryptionConfig tableConfig = DynamoDbTableEncryptionConfig
        .builder()
        .tableName(tableName)
        .schema(schemaWithEncryptedLast4)
        .keyring(keyring)
        .beaconConfig(beaconConfig)
        .build();
      DynamoDbEncryptionInterceptor.builder().tableConfigs(tableConfig).build();
    } catch (InvalidConfigurationException exception) {
      System.err.println(
        "Cache the beacon key for at least one second: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "A beacon key cache time to live of zero was accepted"
    );
  }

  public static void main(String[] args) {
    if (args.length < 4) {
      throw new IllegalArgumentException(
        "To run this example, include the tableName, branchKeyId, keyStoreTableName and " +
        "branchKeyWrappingKmsKeyArn in args"
      );
    }
    buildInvalidBeaconConfigurations(args[0], args[1], args[2], args[3]);
  }
}
