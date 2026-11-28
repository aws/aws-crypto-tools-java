package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling.searchableencryption;

import java.time.Duration;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconKeySource;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.CompoundBeacon;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.CompoundBeaconConstructor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.CompoundBeaconConstructorPart;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.EncryptedPart;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.SignedPart;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.StandardBeacon;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.InvalidItemException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.ValidationException;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;

/**
 * Shows the compound beacon values that the DB-ESDK rejects, on a search and on a write.
 *
 * <p>A compound beacon joins several parts into one searchable value. Each part starts with its
 * prefix, and the beacon's separator character joins the parts. Before anything is sent, the
 * DB-ESDK rejects:
 *
 * <ul>
 *   <li>a search value that starts with no configured part prefix, with {@link
 *       ValidationException};
 *   <li>an item whose part value contains the separator, with {@link InvalidItemException};
 *   <li>an item whose own value for a compound beacon built only from signed parts differs from
 *       the value that the DB-ESDK computes, with {@link InvalidItemException}.
 * </ul>
 *
 * <p>{@link InvalidItemException} is a {@link ValidationException}. Change the value; a retry gets
 * the same result.
 *
 * <p>Running this example needs AWS credentials, a key store, and a branch key in it to use as the
 * beacon key. Every request below is rejected before it is sent, so the table does not have to
 * exist.
 */
public class CompoundBeaconErrorsExample {

  private static final String PARTITION_KEY = "work_id";
  private static final String SORT_KEY = "inspection_date";
  private static final String INSPECTOR_ID_LAST4 = "inspector_id_last4";
  private static final String UNIT = "unit";
  private static final String STATUS = "status";
  private static final String LAST4_UNIT_COMPOUND_BEACON = "last4UnitCompound";
  // A compound beacon built only from signed parts is stored under its own name, so an item can
  // have an attribute with this name.
  private static final String STATUS_COMPOUND_BEACON = "statusCompound";

  public static void sendInvalidCompoundBeaconValues(
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

      // inspector_id_last4 and unit are encrypted; status is signed but not encrypted.
      ItemEncryptionSchema schema = ItemEncryptionSchema
        .builder()
        .partitionKeyName(PARTITION_KEY)
        .sortKeyName(SORT_KEY)
        .encryptAndSign(INSPECTOR_ID_LAST4, UNIT)
        .signOnly(STATUS)
        .build();

      StandardBeacon last4Beacon = StandardBeacon
        .builder()
        .name(INSPECTOR_ID_LAST4)
        .bitLength(10)
        .build();
      StandardBeacon unitBeacon = StandardBeacon
        .builder()
        .name(UNIT)
        .bitLength(30)
        .build();

      // An encrypted part takes the standard beacon whose value it holds.
      EncryptedPart last4EncryptedPart = EncryptedPart
        .builder()
        .beacon(last4Beacon)
        .prefix("L-")
        .build();
      EncryptedPart unitEncryptedPart = EncryptedPart
        .builder()
        .beacon(unitBeacon)
        .prefix("U-")
        .build();
      // A signed part takes the name of the unencrypted attribute whose value it holds.
      SignedPart statusSignedPart = SignedPart
        .builder()
        .name(STATUS)
        .prefix("S-")
        .build();

      // A last4UnitCompound value is "L-<inspector_id_last4>.U-<unit>".
      CompoundBeaconConstructor last4UnitConstructor =
        CompoundBeaconConstructor.of(
          CompoundBeaconConstructorPart.required(last4EncryptedPart),
          CompoundBeaconConstructorPart.required(unitEncryptedPart)
        );
      CompoundBeacon last4UnitCompoundBeacon = CompoundBeacon
        .builder()
        .name(LAST4_UNIT_COMPOUND_BEACON)
        .constructors(last4UnitConstructor)
        .separator('.')
        .build();
      // A statusCompound value is "S-<status>".
      CompoundBeaconConstructor statusConstructor =
        CompoundBeaconConstructor.of(
          CompoundBeaconConstructorPart.required(statusSignedPart)
        );
      CompoundBeacon statusCompoundBeacon = CompoundBeacon
        .builder()
        .name(STATUS_COMPOUND_BEACON)
        .constructors(statusConstructor)
        .separator('.')
        .build();

      BeaconKeySource beaconKeySource = BeaconKeySource
        .singleBeaconKey(branchKeyId)
        .cacheTtl(Duration.ofMinutes(10))
        .build();
      BeaconConfig beaconConfig = BeaconConfig
        .builder()
        .standardBeacons(last4Beacon, unitBeacon)
        .encryptedParts(last4EncryptedPart, unitEncryptedPart)
        .signedParts(statusSignedPart)
        .compoundBeacons(last4UnitCompoundBeacon, statusCompoundBeacon)
        .keyStore(keyStore)
        .keySource(beaconKeySource)
        .build();
      DynamoDbTableEncryptionConfig tableConfig = DynamoDbTableEncryptionConfig
        .builder()
        .tableName(tableName)
        .schema(schema)
        .keyring(hierarchicalKeyring)
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
        scanCompoundValueWithoutPartPrefix(dynamoDbClient, tableName);
        putItemWithSeparatorInPartValue(dynamoDbClient, tableName);
        putItemWithWrongCompoundBeaconValue(dynamoDbClient, tableName);
      }
    }
  }

  // Each part of a compound beacon value starts with its prefix. Here the first part, "4321", has
  // no "L-" prefix.
  private static void scanCompoundValueWithoutPartPrefix(
    DynamoDbClient dynamoDbClient,
    String tableName
  ) {
    ScanRequest request = ScanRequest
      .builder()
      .tableName(tableName)
      .filterExpression(LAST4_UNIT_COMPOUND_BEACON + " = :value")
      .expressionAttributeValues(
        Map.of(":value", AttributeValue.fromS("4321.U-123"))
      )
      .build();
    try {
      dynamoDbClient.scan(request);
    } catch (ValidationException exception) {
      System.err.println(
        "Start each part of a compound beacon value with its prefix: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "A compound beacon value with no part prefix was sent"
    );
  }

  // The separator joins the parts of a compound beacon value, so the DB-ESDK could not tell a part
  // value that contains it from two parts. Here unit is "12.5".
  private static void putItemWithSeparatorInPartValue(
    DynamoDbClient dynamoDbClient,
    String tableName
  ) {
    PutItemRequest request = PutItemRequest
      .builder()
      .tableName(tableName)
      .item(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS("CompoundBeaconErrorsExample"),
          SORT_KEY,
          AttributeValue.fromS("2026-11-17"),
          INSPECTOR_ID_LAST4,
          AttributeValue.fromS("4321"),
          UNIT,
          AttributeValue.fromS("12.5")
        )
      )
      .build();
    try {
      dynamoDbClient.putItem(request);
    } catch (InvalidItemException exception) {
      System.err.println(
        "Keep the separator character out of compound beacon part values: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "An item whose compound beacon part contains the separator was written"
    );
  }

  // The DB-ESDK computes beacon attributes itself when it writes an item, so leave them out of the
  // items that you write.
  // Here the item sets statusCompound to "S-failed", but its status is "passed", so the DB-ESDK
  // computes "S-passed" and rejects the item.
  private static void putItemWithWrongCompoundBeaconValue(
    DynamoDbClient dynamoDbClient,
    String tableName
  ) {
    PutItemRequest request = PutItemRequest
      .builder()
      .tableName(tableName)
      .item(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS("CompoundBeaconErrorsExample"),
          SORT_KEY,
          AttributeValue.fromS("2026-11-17"),
          STATUS,
          AttributeValue.fromS("passed"),
          STATUS_COMPOUND_BEACON,
          AttributeValue.fromS("S-failed")
        )
      )
      .build();
    try {
      dynamoDbClient.putItem(request);
    } catch (InvalidItemException exception) {
      System.err.println(
        "Leave beacon attributes out of the items you write; the DB-ESDK computes them: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "An item with a wrong value for a compound beacon was written"
    );
  }

  public static void main(String[] args) {
    if (args.length < 4) {
      throw new IllegalArgumentException(
        "To run this example, include the tableName, branchKeyId, keyStoreTableName and " +
        "branchKeyWrappingKmsKeyArn in args"
      );
    }
    sendInvalidCompoundBeaconValues(args[0], args[1], args[2], args[3]);
  }
}
