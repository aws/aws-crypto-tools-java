package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling;

import java.time.Duration;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconKeySource;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.PartitionSelector;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.StandardBeacon;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.CustomComponentException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.EncryptedTableResource;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.ValidationException;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;

/**
 * Shows how a partition selector that you implemented can fail, and what the DB-ESDK throws for
 * each.
 *
 * <p>A beacon configuration with more than one partition spreads each beacon's values over several
 * partitions, and a partition selector picks the partition for each item that the DB-ESDK writes.
 *
 * <ul>
 *   <li>When your selector throws, the DB-ESDK throws {@link CustomComponentException} with your
 *       selector's exception as its cause.
 *   <li>When your selector returns a partition number out of range, the DB-ESDK throws {@link
 *       ValidationException}.
 * </ul>
 *
 * <p>The DB-ESDK does not send the write in either case.
 *
 * <p>Running this example needs AWS credentials, a key store, and a branch key in it to use as the
 * beacon key. Every request below is rejected before it is sent, so the table does not have to
 * exist.
 */
public class PartitionSelectorErrorsExample {

  private static final String PARTITION_KEY = "work_id";
  private static final String SORT_KEY = "inspection_date";
  private static final String INSPECTOR_ID_LAST4 = "inspector_id_last4";
  private static final String UNIT = "unit";

  public static void partitionSelectorErrors(
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

      ItemEncryptionSchema schema = ItemEncryptionSchema
        .builder()
        .partitionKeyName(PARTITION_KEY)
        .sortKeyName(SORT_KEY)
        .encryptAndSign(INSPECTOR_ID_LAST4, UNIT)
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
      BeaconKeySource beaconKeySource = BeaconKeySource
        .singleBeaconKey(branchKeyId)
        .cacheTtl(Duration.ofMinutes(10))
        .build();

      // Throws for an item that has no inspector_id_last4.
      PartitionSelector byInspector = (
        item,
        numberOfPartitions,
        logicalTableName
      ) -> {
        AttributeValue last4 = item.get(INSPECTOR_ID_LAST4);
        if (last4 == null) {
          throw new NoInspectorException();
        }
        return Math.floorMod(last4.s().hashCode(), numberOfPartitions);
      };
      // Partitions are numbered from 0 to numberOfPartitions - 1, so this selector returns one past
      // the last partition.
      PartitionSelector onePastLastPartition = (
          item,
          numberOfPartitions,
          logicalTableName
        ) ->
        numberOfPartitions;

      // With two partitions, the DB-ESDK calls the partition selector for each item that it writes.
      // Each selector needs its own beacon configuration, table configuration and client.
      BeaconConfig byInspectorBeaconConfig = BeaconConfig
        .builder()
        .standardBeacons(last4Beacon, unitBeacon)
        .maximumNumberOfPartitions(2)
        .partitionSelector(byInspector)
        .keyStore(keyStore)
        .keySource(beaconKeySource)
        .build();
      DynamoDbTableEncryptionConfig byInspectorTableConfig =
        DynamoDbTableEncryptionConfig
          .builder()
          .tableName(tableName)
          .schema(schema)
          .keyring(hierarchicalKeyring)
          .beaconConfig(byInspectorBeaconConfig)
          .build();
      DynamoDbEncryptionInterceptor byInspectorInterceptor =
        DynamoDbEncryptionInterceptor
          .builder()
          .tableConfigs(byInspectorTableConfig)
          .build();

      BeaconConfig onePastLastBeaconConfig = BeaconConfig
        .builder()
        .standardBeacons(last4Beacon, unitBeacon)
        .maximumNumberOfPartitions(2)
        .partitionSelector(onePastLastPartition)
        .keyStore(keyStore)
        .keySource(beaconKeySource)
        .build();
      DynamoDbTableEncryptionConfig onePastLastTableConfig =
        DynamoDbTableEncryptionConfig
          .builder()
          .tableName(tableName)
          .schema(schema)
          .keyring(hierarchicalKeyring)
          .beaconConfig(onePastLastBeaconConfig)
          .build();
      DynamoDbEncryptionInterceptor onePastLastInterceptor =
        DynamoDbEncryptionInterceptor
          .builder()
          .tableConfigs(onePastLastTableConfig)
          .build();

      PutItemRequest writeWithoutInspector = PutItemRequest
        .builder()
        .tableName(tableName)
        .item(
          Map.of(
            PARTITION_KEY,
            AttributeValue.fromS("PartitionSelectorErrorsExample"),
            SORT_KEY,
            AttributeValue.fromS("2026-11-17"),
            UNIT,
            AttributeValue.fromS("123")
          )
        )
        .build();

      try (
        DynamoDbClient clientWithThrowingSelector = DynamoDbClient
          .builder()
          .overrideConfiguration(overrides ->
            overrides.addExecutionInterceptor(byInspectorInterceptor)
          )
          .build();
        DynamoDbClient clientWithOutOfRangeSelector = DynamoDbClient
          .builder()
          .overrideConfiguration(overrides ->
            overrides.addExecutionInterceptor(onePastLastInterceptor)
          )
          .build()
      ) {
        partitionSelectorThatThrows(
          clientWithThrowingSelector,
          writeWithoutInspector
        );
        partitionSelectorOutOfRange(
          clientWithOutOfRangeSelector,
          writeWithoutInspector
        );
      }
    }
  }

  /** Thrown by this application's partition selector for an item that it cannot place. */
  static final class NoInspectorException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    NoInspectorException() {
      super("The item has no " + INSPECTOR_ID_LAST4);
    }
  }

  // The DB-ESDK calls the partition selector for each item that PutItem, BatchWriteItem or a
  // TransactWriteItems Put writes. An exception that the selector throws arrives as the cause of a
  // CustomComponentException, whose resource() is the table whose configuration holds the
  // selector.
  private static void partitionSelectorThatThrows(
    DynamoDbClient dynamoDbClient,
    PutItemRequest request
  ) {
    try {
      dynamoDbClient.putItem(request);
    } catch (CustomComponentException exception) {
      if (
        exception.getCause() instanceof NoInspectorException noInspector &&
        exception.resource() instanceof EncryptedTableResource table
      ) {
        System.err.println(
          "The partition selector for table " +
          table.name() +
          " could not place the item: " +
          noInspector.getMessage()
        );
        return;
      }
      throw exception;
    }
    throw new IllegalStateException(
      "A write whose partition selector threw was sent"
    );
  }

  private static void partitionSelectorOutOfRange(
    DynamoDbClient dynamoDbClient,
    PutItemRequest request
  ) {
    try {
      dynamoDbClient.putItem(request);
    } catch (ValidationException exception) {
      System.err.println(
        "Return a partition from 0 to numberOfPartitions - 1: " +
        exception.getMessage()
      );
      return;
    }
    throw new IllegalStateException(
      "A write with an out-of-range partition was sent"
    );
  }

  public static void main(String[] args) {
    if (args.length < 4) {
      throw new IllegalArgumentException(
        "To run this example, include the tableName, branchKeyId, keyStoreTableName and " +
        "branchKeyWrappingKmsKeyArn in args"
      );
    }
    partitionSelectorErrors(args[0], args[1], args[2], args[3]);
  }
}
