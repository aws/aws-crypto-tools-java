package software.amazon.cryptography.dbesdk.examples.searchableencryption.complexexample;

import java.time.Duration;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconKeySource;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.CompoundBeacon;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.CompoundBeaconConstructor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.EncryptedPart;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.SignedPart;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.StandardBeacon;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;

/**
 * This class is used in an example to demonstrate complex queries you can perform using beacons.
 * The example data used is for demonstrative purposes only, and might not meet the distribution
 * and correlation uniqueness recommendations for beacons. See our documentation for whether
 * beacons are right for your particular data set:
 * https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/searchable-encryption.html#are-beacons-right-for-me
 *
 * <p>This file sets up all the searchable encryption configuration that the complex searchable
 * encryption example needs, using the encryption client.
 */
public final class ComplexExampleClientSetup {

  private ComplexExampleClientSetup() {}

  public static DynamoDbClient createDynamoDbClient(
    String tableName,
    String branchKeyId,
    String branchKeyWrappingKmsKeyArn,
    String keyStoreTableName,
    DynamoDbClient keyStoreDynamoDbClient,
    KmsClient keyStoreKmsClient
  ) {
    // 1. Create Keystore and branch key.
    //    These are the same constructions as in the Basic examples, which describe this in more detail.
    //    The keystore uses the caller's DynamoDB and AWS KMS clients. The returned client uses the
    //    keystore, so the caller must keep those clients open until it has closed the returned client.
    BranchKeyStore keyStore = BranchKeyStore
      .builder()
      .ddbTableName(keyStoreTableName)
      .logicalKeyStoreName(keyStoreTableName)
      .kmsConfiguration(KmsConfiguration.kmsKeyArn(branchKeyWrappingKmsKeyArn))
      .ddbClient(keyStoreDynamoDbClient)
      .kmsClient(keyStoreKmsClient)
      .build();

    // 2. Define constructors
    //    A constructor is one allowed way to assemble a compound beacon value: an ordered list of
    //    the compound beacon's encrypted and signed parts, joined by its separator. addRequiredPart
    //    and addOptionalPart each take one or more part names, and the parts are written in the
    //    order they are given, across calls. When an item is written, the compound beacon's
    //    constructors are tried in order, and the first one whose required parts are all on the
    //    item is used; an optional part that is missing is left out. The constructors below build
    //    the PK and SK values for each record type in this example. All their parts are required.

    // The employee ID constructor only requires an employee ID.
    // If an item has an attribute with name "EmployeeID", it will match this constructor.
    // If this is the first matching constructor in the constructor list (constructor list
    // described more below), the compound beacon will use this constructor, and the compound
    // beacon will be written as `E-X`.
    CompoundBeaconConstructor employeeIdConstructor = CompoundBeaconConstructor
      .builder()
      .addRequiredPart("EmployeeID")
      .build();

    CompoundBeaconConstructor ticketNumberConstructor =
      CompoundBeaconConstructor
        .builder()
        .addRequiredPart("TicketNumber")
        .build();

    CompoundBeaconConstructor projectNameConstructor = CompoundBeaconConstructor
      .builder()
      .addRequiredPart("ProjectName")
      .build();

    CompoundBeaconConstructor ticketModTimeConstructor =
      CompoundBeaconConstructor
        .builder()
        .addRequiredPart("TicketModTime")
        .build();

    CompoundBeaconConstructor buildingConstructor = CompoundBeaconConstructor
      .builder()
      .addRequiredPart("Building")
      .build();

    // This constructor requires all of "MeetingStart", "Location.Floor", and "Location.Room"
    // attributes. If an item has all of these attributes, it will match this constructor.
    // If this is the first matching constructor in the constructor list (constructor list
    // described more below), the compound beacon will use this constructor, and the compound
    // beacon will be written as `MS-X~F-Y~R-Z`.
    // In a constructor with more than one part, the order of the part names defines the order the
    // parts are written in. Reordering them reorders the beacon value.
    CompoundBeaconConstructor meetingStartFloorRoomConstructor =
      CompoundBeaconConstructor
        .builder()
        .addRequiredPart("MeetingStart", "Floor", "Room")
        .build();

    CompoundBeaconConstructor timeCardStartEmployeeEmailConstructor =
      CompoundBeaconConstructor
        .builder()
        .addRequiredPart("TimeCardStart", "EmployeeEmail")
        .build();

    CompoundBeaconConstructor timeCardStartConstructor =
      CompoundBeaconConstructor
        .builder()
        .addRequiredPart("TimeCardStart")
        .build();

    CompoundBeaconConstructor creatorEmailConstructor =
      CompoundBeaconConstructor
        .builder()
        .addRequiredPart("CreatorEmail")
        .build();

    CompoundBeaconConstructor projectStatusConstructor =
      CompoundBeaconConstructor
        .builder()
        .addRequiredPart("ProjectStatus")
        .build();

    CompoundBeaconConstructor employeeEmailConstructor =
      CompoundBeaconConstructor
        .builder()
        .addRequiredPart("EmployeeEmail")
        .build();

    CompoundBeaconConstructor organizerEmailConstructor =
      CompoundBeaconConstructor
        .builder()
        .addRequiredPart("OrganizerEmail")
        .build();

    CompoundBeaconConstructor projectStartConstructor =
      CompoundBeaconConstructor
        .builder()
        .addRequiredPart("ProjectStart")
        .build();

    CompoundBeaconConstructor managerEmailConstructor =
      CompoundBeaconConstructor
        .builder()
        .addRequiredPart("ManagerEmail")
        .build();

    CompoundBeaconConstructor assigneeEmailConstructor =
      CompoundBeaconConstructor
        .builder()
        .addRequiredPart("AssigneeEmail")
        .build();

    CompoundBeaconConstructor cityConstructor = CompoundBeaconConstructor
      .builder()
      .addRequiredPart("City")
      .build();

    CompoundBeaconConstructor severityConstructor = CompoundBeaconConstructor
      .builder()
      .addRequiredPart("Severity")
      .build();

    CompoundBeaconConstructor buildingFloorDeskConstructor =
      CompoundBeaconConstructor
        .builder()
        .addRequiredPart("Building", "Floor", "Desk")
        .build();

    // 3. Create BeaconConfig.
    //    The standard beacons, encrypted parts, signed parts and compound beacons are passed
    //    directly to the builder below.
    BeaconConfig beaconConfig = BeaconConfig
      .builder()
      // Create standard beacons
      // For this example, we use a standard beacon length of 4.
      // The BasicSearchableEncryptionExample gives a more thorough consideration of beacon length.
      // For production applications, one should always exercise rigor when deciding beacon length, including
      //     examining population size and considering performance.
      .standardBeacons(
        StandardBeacon.builder().name("EmployeeID").bitLength(4).build(),
        StandardBeacon.builder().name("TicketNumber").bitLength(4).build(),
        StandardBeacon.builder().name("ProjectName").bitLength(4).build(),
        StandardBeacon.builder().name("EmployeeEmail").bitLength(4).build(),
        StandardBeacon.builder().name("CreatorEmail").bitLength(4).build(),
        StandardBeacon.builder().name("ProjectStatus").bitLength(4).build(),
        StandardBeacon.builder().name("OrganizerEmail").bitLength(4).build(),
        StandardBeacon.builder().name("ManagerEmail").bitLength(4).build(),
        StandardBeacon.builder().name("AssigneeEmail").bitLength(4).build(),
        StandardBeacon
          .builder()
          .name("City")
          .location("Location.City")
          .bitLength(4)
          .build(),
        StandardBeacon.builder().name("Severity").bitLength(4).build(),
        StandardBeacon
          .builder()
          .name("Building")
          .location("Location.Building")
          .bitLength(4)
          .build(),
        StandardBeacon
          .builder()
          .name("Floor")
          .location("Location.Floor")
          .bitLength(4)
          .build(),
        StandardBeacon
          .builder()
          .name("Room")
          .location("Location.Room")
          .bitLength(4)
          .build(),
        StandardBeacon
          .builder()
          .name("Desk")
          .location("Location.Desk")
          .bitLength(4)
          .build()
      )
      // Define compound beacons
      // Compound beacon construction is defined in more detail in CompoundBeaconSearchableEncryptionExample.
      // Note that the separator must not appear in any prefix, or in any value written into the
      // compound beacon. Writing an item fails if one of those values contains it.
      //
      // Add constructors to each compound beacon's constructor list in desired construction order.
      // In a compound beacon with multiple constructors, the order the constructors are added to
      //     the constructor list determines their priority.
      // The first constructor added to a constructor list will be the first constructor that is executed.
      // The client will evaluate constructors until one matches, and will use the first one that matches.
      // If no constructors match, an attribute value is not written for that beacon.
      // A general strategy is to add constructors with unique conditions at the beginning of the list,
      //    and add constructors with general conditions at the end of the list. This would allow a given
      //    item would trigger the constructor most specific to its attributes.
      .compoundBeacons(
        CompoundBeacon
          .builder()
          .name("PK")
          .separator('~')
          .constructors(
            employeeIdConstructor,
            buildingConstructor,
            ticketNumberConstructor,
            projectNameConstructor
          )
          .build(),
        CompoundBeacon
          .builder()
          .name("SK")
          .separator('~')
          .constructors(
            ticketModTimeConstructor,
            meetingStartFloorRoomConstructor,
            timeCardStartEmployeeEmailConstructor,
            projectNameConstructor,
            employeeIdConstructor
          )
          .build(),
        CompoundBeacon
          .builder()
          .name("PK1")
          .separator('~')
          .constructors(
            creatorEmailConstructor,
            employeeEmailConstructor,
            projectStatusConstructor,
            organizerEmailConstructor
          )
          .build(),
        CompoundBeacon
          .builder()
          .name("SK1")
          .separator('~')
          .constructors(
            meetingStartFloorRoomConstructor,
            timeCardStartConstructor,
            ticketModTimeConstructor,
            projectStartConstructor,
            employeeIdConstructor
          )
          .build(),
        CompoundBeacon
          .builder()
          .name("PK2")
          .separator('~')
          .constructors(managerEmailConstructor, assigneeEmailConstructor)
          .build(),
        CompoundBeacon
          .builder()
          .name("PK3")
          .separator('~')
          .constructors(cityConstructor, severityConstructor)
          .build(),
        CompoundBeacon
          .builder()
          .name("SK3")
          .separator('~')
          .constructors(buildingFloorDeskConstructor, ticketModTimeConstructor)
          .build()
      )
      // Define encrypted parts
      // Every prefix must be unique within one configuration.
      // Encrypted parts are described in more detail in the CompoundBeaconSearchableEncryptionExample.
      .encryptedParts(
        EncryptedPart.builder().name("EmployeeID").prefix("E-").build(),
        EncryptedPart.builder().name("TicketNumber").prefix("T-").build(),
        EncryptedPart.builder().name("ProjectName").prefix("P-").build(),
        EncryptedPart.builder().name("EmployeeEmail").prefix("EE-").build(),
        EncryptedPart.builder().name("CreatorEmail").prefix("CE-").build(),
        EncryptedPart.builder().name("ProjectStatus").prefix("PSts-").build(),
        EncryptedPart.builder().name("OrganizerEmail").prefix("OE-").build(),
        EncryptedPart.builder().name("ManagerEmail").prefix("ME-").build(),
        EncryptedPart.builder().name("AssigneeEmail").prefix("AE-").build(),
        EncryptedPart.builder().name("City").prefix("C-").build(),
        EncryptedPart.builder().name("Severity").prefix("S-").build(),
        EncryptedPart.builder().name("Building").prefix("B-").build(),
        EncryptedPart.builder().name("Floor").prefix("F-").build(),
        EncryptedPart.builder().name("Room").prefix("R-").build(),
        EncryptedPart.builder().name("Desk").prefix("D-").build()
      )
      // Define signed parts.
      // These are unencrypted attributes we would like to use in beacon queries.
      // In this example, all of these represent dates or times.
      // Keeping these attributes unencrypted allows us to use them in comparison-based queries.
      // If a signed part is the first part in a compound beacon, then that part can be used in
      // comparison for sorting.
      .signedParts(
        SignedPart.builder().name("TicketModTime").prefix("M-").build(),
        SignedPart.builder().name("MeetingStart").prefix("MS-").build(),
        SignedPart.builder().name("TimeCardStart").prefix("TC-").build(),
        SignedPart.builder().name("ProjectStart").prefix("PS-").build()
      )
      .keyStore(keyStore)
      .keySource(
        BeaconKeySource
          .singleBeaconKey(branchKeyId)
          .cacheTtl(Duration.ofSeconds(6000))
          .build()
      )
      .build();

    // 4. Create a Hierarchical Keyring
    Keyring kmsKeyring = AwsKmsHierarchicalKeyring
      .builder()
      .branchKeyId(branchKeyId)
      .keyStore(keyStore)
      .ttl(Duration.ofSeconds(6000))
      .build();

    // 5. Decide how each attribute of your items is protected. BasicPutGetExample
    //    explains each action (encryptAndSign, signOnly, signAndIncludeInEncryptionContext,
    //    doNothing), and why the partition and sort keys get none.
    //     Every attribute you write must have an action; writing an item with any other attribute
    //     fails.

    // Build the schema from these choices.
    ItemEncryptionSchema schema = ItemEncryptionSchema
      .builder()
      .partitionKeyName("partition_key")
      .encryptAndSign(
        // Attributes used in beacons must be configured as ENCRYPT_AND_SIGN
        "EmployeeID",
        "TicketNumber",
        "ProjectName",
        "EmployeeName",
        "EmployeeEmail",
        "CreatorEmail",
        "ProjectStatus",
        "OrganizerEmail",
        "ManagerEmail",
        "AssigneeEmail",
        "City",
        "Severity",
        "Location",
        // These are not beaconized attributes, but are sensitive data that must be encrypted
        "Attendees",
        "Subject"
      )
      // signed parts and unencrypted attributes can be configured as SIGN_ONLY or DO_NOTHING
      // For this example, we will set these to SIGN_ONLY to ensure authenticity
      .signOnly(
        "TicketModTime",
        "MeetingStart",
        "TimeCardStart",
        "EmployeeTitle",
        "Description",
        "ProjectTarget",
        "Hours",
        "Role",
        "Message",
        "ProjectStart",
        "Duration"
      )
      .build();

    // 6. Set up table config
    DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .logicalTableName(tableName)
      .schema(schema)
      .keyring(kmsKeyring)
      .beaconConfig(beaconConfig)
      .build();

    // 7. Create the DynamoDB Encryption Interceptor
    DynamoDbEncryptionInterceptor encryptionInterceptor =
      DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();

    // 8. Create a new AWS SDK DynamoDB client using the DynamoDB Encryption Interceptor above
    DynamoDbClient dynamoDbClient = DynamoDbClient
      .builder()
      .overrideConfiguration(overrides ->
        overrides.addExecutionInterceptor(encryptionInterceptor)
      )
      .build();

    return dynamoDbClient;
  }
}
