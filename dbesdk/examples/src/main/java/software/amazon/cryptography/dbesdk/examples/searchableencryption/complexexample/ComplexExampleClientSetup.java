package software.amazon.cryptography.dbesdk.examples.searchableencryption.complexexample;

import java.time.Duration;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconKeySource;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.BeaconConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.CompoundBeacon;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.Constructor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ConstructorPart;
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

public class ComplexExampleClientSetup {

  /*
   * This file is used in an example to demonstrate complex queries you can perform using beacons.
   * The example data used is for demonstrative purposes only, and might not meet the distribution
   * and correlation uniqueness recommendations for beacons. See our documentation for whether
   * beacons are right for your particular data set:
   * https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/searchable-encryption.html#are-beacons-right-for-me
   *
   * This file sets up all the searchable encryption configuration required to execute the examples
   * from our workshop using the encryption client.
   */

  public static DynamoDbClient createDynamoDbClient(
    String tableName,
    String branchKeyId,
    String branchKeyWrappingKmsKeyArn,
    String keyStoreTableName
  ) {
    // 1. Create Keystore and branch key.
    //    These are the same constructions as in the Basic examples, which describe this in more detail.
    final BranchKeyStore keyStore = BranchKeyStore
      .builder()
      .kmsClient(KmsClient.create())
      .ddbClient(DynamoDbClient.create())
      .ddbTableName(keyStoreTableName)
      .logicalKeyStoreName(keyStoreTableName)
      .kmsConfiguration(KmsConfiguration.kmsKeyArn(branchKeyWrappingKmsKeyArn))
      .build();

    // 2. Create constructor parts.
    //    Constructor parts are used to assemble constructors (constructors described more in next step).
    //    For each attribute that will be used in a constructor, there must be a corresponding constructor part.
    //    A constructor part must receive:
    //     - name: Name of a standard beacon
    //     - required: Whether this attribute must be present in the item to match a constructor
    //    In this example, we will define each constructor part once and re-use it across multiple constructors.
    //    The parts below are defined by working backwards from the constructors in "PK Constructors",
    //        "SK constructors", etc. sections in Demo.md.
    final ConstructorPart employeeIdConstructorPart = ConstructorPart
      .builder()
      // This name comes from the "EmployeeID" standard beacon.
      .name("EmployeeID")
      .required(true)
      .build();
    final ConstructorPart ticketNumberConstructorPart = ConstructorPart
      .builder()
      .name("TicketNumber")
      .required(true)
      .build();
    final ConstructorPart projectNameConstructorPart = ConstructorPart
      .builder()
      .name("ProjectName")
      .required(true)
      .build();
    final ConstructorPart ticketModTimeConstructorPart = ConstructorPart
      .builder()
      .name("TicketModTime")
      .required(true)
      .build();
    final ConstructorPart meetingStartConstructorPart = ConstructorPart
      .builder()
      .name("MeetingStart")
      .required(true)
      .build();
    final ConstructorPart timeCardStartConstructorPart = ConstructorPart
      .builder()
      .name("TimeCardStart")
      .required(true)
      .build();
    final ConstructorPart employeeEmailConstructorPart = ConstructorPart
      .builder()
      .name("EmployeeEmail")
      .required(true)
      .build();
    final ConstructorPart creatorEmailConstructorPart = ConstructorPart
      .builder()
      .name("CreatorEmail")
      .required(true)
      .build();
    final ConstructorPart projectStatusConstructorPart = ConstructorPart
      .builder()
      .name("ProjectStatus")
      .required(true)
      .build();
    final ConstructorPart organizerEmailConstructorPart = ConstructorPart
      .builder()
      .name("OrganizerEmail")
      .required(true)
      .build();
    final ConstructorPart projectStartConstructorPart = ConstructorPart
      .builder()
      .name("ProjectStart")
      .required(true)
      .build();
    final ConstructorPart managerEmailConstructorPart = ConstructorPart
      .builder()
      .name("ManagerEmail")
      .required(true)
      .build();
    final ConstructorPart assigneeEmailConstructorPart = ConstructorPart
      .builder()
      .name("AssigneeEmail")
      .required(true)
      .build();
    final ConstructorPart cityConstructorPart = ConstructorPart
      .builder()
      .name("City")
      .required(true)
      .build();
    final ConstructorPart severityConstructorPart = ConstructorPart
      .builder()
      .name("Severity")
      .required(true)
      .build();
    final ConstructorPart buildingConstructorPart = ConstructorPart
      .builder()
      .name("Building")
      .required(true)
      .build();
    final ConstructorPart floorConstructorPart = ConstructorPart
      .builder()
      .name("Floor")
      .required(true)
      .build();
    final ConstructorPart roomConstructorPart = ConstructorPart
      .builder()
      .name("Room")
      .required(true)
      .build();
    final ConstructorPart deskConstructorPart = ConstructorPart
      .builder()
      .name("Desk")
      .required(true)
      .build();

    // 3. Define constructors
    //    Constructors define how encrypted and signed parts are assembled into compound beacons.
    //    The constructors below are based off of the "PK Constructors", "SK constructors", etc. sections in Demo.md.

    // The employee ID constructor only requires an employee ID.
    // If an item has an attribute with name "EmployeeID", it will match this constructor.
    // If this is the first matching constructor in the constructor list (constructor list described more below),
    //     the compound beacon will use this constructor, and the compound beacon will be written as `E-X`.
    final Constructor employeeIdConstructor = Constructor
      .builder()
      .parts(employeeIdConstructorPart)
      .build();

    final Constructor ticketNumberConstructor = Constructor
      .builder()
      .parts(ticketNumberConstructorPart)
      .build();

    final Constructor projectNameConstructor = Constructor
      .builder()
      .parts(projectNameConstructorPart)
      .build();

    final Constructor ticketModTimeConstructor = Constructor
      .builder()
      .parts(ticketModTimeConstructorPart)
      .build();

    final Constructor buildingConstructor = Constructor
      .builder()
      .parts(buildingConstructorPart)
      .build();

    // This constructor requires all of "MeetingStart", "Location.Floor", and "Location.Room" attributes.
    // If an item has all of these attributes, it will match this constructor.
    // If this is the first matching constructor in the constructor list (constructor list described more below),
    //     the compound beacon will use this constructor, and the compound beacon will be written as `MS-X~F-Y~R-Z`.
    // In a constructor with multiple constructor parts, the order the constructor parts are added to
    //     the constructor part list defines how the compound beacon is written.
    // We can rearrange the beacon parts by changing the order the constructors were added to the list.
    final Constructor meetingStartFloorRoomConstructor = Constructor
      .builder()
      .parts(
          meetingStartConstructorPart,
          floorConstructorPart,
          roomConstructorPart
        )
      .build();

    final Constructor timeCardStartEmployeeEmailConstructor = Constructor
      .builder()
      .parts(timeCardStartConstructorPart, employeeEmailConstructorPart)
      .build();

    final Constructor timeCardStartConstructor = Constructor
      .builder()
      .parts(timeCardStartConstructorPart)
      .build();

    final Constructor creatorEmailConstructor = Constructor
      .builder()
      .parts(creatorEmailConstructorPart)
      .build();

    final Constructor projectStatusConstructor = Constructor
      .builder()
      .parts(projectStatusConstructorPart)
      .build();

    final Constructor employeeEmailConstructor = Constructor
      .builder()
      .parts(employeeEmailConstructorPart)
      .build();

    final Constructor organizerEmailConstructor = Constructor
      .builder()
      .parts(organizerEmailConstructorPart)
      .build();

    final Constructor projectStartConstructor = Constructor
      .builder()
      .parts(projectStartConstructorPart)
      .build();

    final Constructor managerEmailConstructor = Constructor
      .builder()
      .parts(managerEmailConstructorPart)
      .build();

    final Constructor assigneeEmailConstructor = Constructor
      .builder()
      .parts(assigneeEmailConstructorPart)
      .build();

    final Constructor cityConstructor = Constructor
      .builder()
      .parts(cityConstructorPart)
      .build();

    final Constructor severityConstructor = Constructor
      .builder()
      .parts(severityConstructorPart)
      .build();

    final Constructor buildingFloorDeskConstructor = Constructor
      .builder()
      .parts(
          buildingConstructorPart,
          floorConstructorPart,
          deskConstructorPart
        )
      .build();

    // 4. Create BeaconConfig.
    //    The standard beacons, encrypted parts, signed parts and compound beacons are passed
    //    directly to the builder below.
    final BeaconConfig beaconConfig = BeaconConfig
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
      // Note that the split character must be a character that is not used in any attribute value.
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
          .split("~")
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
          .split("~")
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
          .split("~")
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
          .split("~")
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
          .split("~")
          .constructors(managerEmailConstructor, assigneeEmailConstructor)
          .build(),
        CompoundBeacon
          .builder()
          .name("PK3")
          .split("~")
          .constructors(cityConstructor, severityConstructor)
          .build(),
        CompoundBeacon
          .builder()
          .name("SK3")
          .split("~")
          .constructors(buildingFloorDeskConstructor, ticketModTimeConstructor)
          .build()
      )
      // Define encrypted parts
      // Note that some of the prefixes are modified from the suggested prefixes in Demo.md.
      // This is because all prefixes must be unique in a configuration.
      // Encrypted parts are described in more detail in the CompoundBeaconSearcbaleEncryptionExample.
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
      // Keeping these attributes unencrypted allows us to use them in comparison-based queries. If a signed
      //     part is the first part in a compound beacon, then that part can be used in comparison for sorting.
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

    // 5. Create a Hierarchical Keyring
    final Keyring kmsKeyring = AwsKmsHierarchicalKeyring
      .builder()
      .branchKeyId(branchKeyId)
      .keyStore(keyStore)
      .ttl(Duration.ofSeconds(6000))
      .build();

    // 6. Decide how each attribute of your items is protected. Give each attribute one of these
    //     actions:
    //     - encryptAndSign: the value is encrypted, so it cannot be read without the keys your
    //       keyring uses, and it is covered by the item's signature, so any change to it is
    //       detected when the item is read.
    //     - signOnly: the value is stored as plain, readable text, but it is covered by the
    //       signature, so any change to it is detected.
    //     - signAndIncludeInEncryptionContext: like signOnly, and the value is also handed to your
    //       keyring each time the item is encrypted or decrypted, for example so that a branch key
    //       ID supplier can pick a different key for each tenant. Using this action also requires
    //       signAndIncludePrimaryKeysInEncryptionContext(true) (see below).
    //     - doNothing: the value is stored as plain text and is not covered by the signature, so a
    //       change to it is NOT detected.
    //     Every attribute you write must have an action; writing an item with any other attribute
    //     fails.
    //
    //     Do not give the partition key or the sort key (together, the table's primary key) an
    //     action. DynamoDB needs to read them to find the item, so they can never be encrypted, and
    //     the library always signs them for you. By default they are signed like signOnly, and
    //     their values are still handed to your keyring, in an encoded form. If you call
    //     signAndIncludePrimaryKeysInEncryptionContext(true), they are signed like
    //     signAndIncludeInEncryptionContext instead: their values are handed to your keyring as
    //     plain text, and you can give other attributes the signAndIncludeInEncryptionContext
    //     action.

    // Build the schema from these choices.
    final ItemEncryptionSchema schema = ItemEncryptionSchema
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

    // 7. Set up table config
    final DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .logicalTableName(tableName)
      .schema(schema)
      .keyring(kmsKeyring)
      .beaconConfig(beaconConfig)
      .build();

    // 8. Create the DynamoDB Encryption Interceptor
    final DynamoDbEncryptionInterceptor encryptionInterceptor =
      DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();

    // 9. Create a new AWS SDK DynamoDB client using the DynamoDB Encryption Interceptor above
    final DynamoDbClient dynamoDbClient = DynamoDbClient
      .builder()
      .overrideConfiguration(overrides ->
        overrides.addExecutionInterceptor(encryptionInterceptor)
      )
      .build();

    return dynamoDbClient;
  }
}
