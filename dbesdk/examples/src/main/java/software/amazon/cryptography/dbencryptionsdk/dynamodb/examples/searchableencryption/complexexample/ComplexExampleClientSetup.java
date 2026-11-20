package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.searchableencryption.complexexample;

import java.time.Duration;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
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

    // 2. Define the standard beacons, encrypted parts, signed parts and constructors.

    // Standard beacons
    // For this example, we use a standard beacon length of 4.
    // The BasicSearchableEncryptionExample gives a more thorough consideration of beacon length.
    // For production applications, one should always exercise rigor when deciding beacon length,
    // including examining population size and considering performance.
    StandardBeacon employeeIdBeacon = StandardBeacon
      .builder()
      .name("EmployeeID")
      .bitLength(4)
      .build();
    StandardBeacon ticketNumberBeacon = StandardBeacon
      .builder()
      .name("TicketNumber")
      .bitLength(4)
      .build();
    StandardBeacon projectNameBeacon = StandardBeacon
      .builder()
      .name("ProjectName")
      .bitLength(4)
      .build();
    StandardBeacon employeeEmailBeacon = StandardBeacon
      .builder()
      .name("EmployeeEmail")
      .bitLength(4)
      .build();
    StandardBeacon creatorEmailBeacon = StandardBeacon
      .builder()
      .name("CreatorEmail")
      .bitLength(4)
      .build();
    StandardBeacon projectStatusBeacon = StandardBeacon
      .builder()
      .name("ProjectStatus")
      .bitLength(4)
      .build();
    StandardBeacon organizerEmailBeacon = StandardBeacon
      .builder()
      .name("OrganizerEmail")
      .bitLength(4)
      .build();
    StandardBeacon managerEmailBeacon = StandardBeacon
      .builder()
      .name("ManagerEmail")
      .bitLength(4)
      .build();
    StandardBeacon assigneeEmailBeacon = StandardBeacon
      .builder()
      .name("AssigneeEmail")
      .bitLength(4)
      .build();
    StandardBeacon cityBeacon = StandardBeacon
      .builder()
      .name("City")
      .location("Location.City")
      .bitLength(4)
      .build();
    StandardBeacon severityBeacon = StandardBeacon
      .builder()
      .name("Severity")
      .bitLength(4)
      .build();
    StandardBeacon buildingBeacon = StandardBeacon
      .builder()
      .name("Building")
      .location("Location.Building")
      .bitLength(4)
      .build();
    StandardBeacon floorBeacon = StandardBeacon
      .builder()
      .name("Floor")
      .location("Location.Floor")
      .bitLength(4)
      .build();
    StandardBeacon roomBeacon = StandardBeacon
      .builder()
      .name("Room")
      .location("Location.Room")
      .bitLength(4)
      .build();
    StandardBeacon deskBeacon = StandardBeacon
      .builder()
      .name("Desk")
      .location("Location.Desk")
      .bitLength(4)
      .build();

    // Encrypted parts
    // Each encrypted part takes the standard beacon whose value it holds. Every prefix must be
    // unique within one configuration. Encrypted parts are described in more detail in the
    // CompoundBeaconSearchableEncryptionExample.
    EncryptedPart employeeIdPart = EncryptedPart
      .builder()
      .beacon(employeeIdBeacon)
      .prefix("E-")
      .build();
    EncryptedPart ticketNumberPart = EncryptedPart
      .builder()
      .beacon(ticketNumberBeacon)
      .prefix("T-")
      .build();
    EncryptedPart projectNamePart = EncryptedPart
      .builder()
      .beacon(projectNameBeacon)
      .prefix("P-")
      .build();
    EncryptedPart employeeEmailPart = EncryptedPart
      .builder()
      .beacon(employeeEmailBeacon)
      .prefix("EE-")
      .build();
    EncryptedPart creatorEmailPart = EncryptedPart
      .builder()
      .beacon(creatorEmailBeacon)
      .prefix("CE-")
      .build();
    EncryptedPart projectStatusPart = EncryptedPart
      .builder()
      .beacon(projectStatusBeacon)
      .prefix("PSts-")
      .build();
    EncryptedPart organizerEmailPart = EncryptedPart
      .builder()
      .beacon(organizerEmailBeacon)
      .prefix("OE-")
      .build();
    EncryptedPart managerEmailPart = EncryptedPart
      .builder()
      .beacon(managerEmailBeacon)
      .prefix("ME-")
      .build();
    EncryptedPart assigneeEmailPart = EncryptedPart
      .builder()
      .beacon(assigneeEmailBeacon)
      .prefix("AE-")
      .build();
    EncryptedPart cityPart = EncryptedPart
      .builder()
      .beacon(cityBeacon)
      .prefix("C-")
      .build();
    EncryptedPart severityPart = EncryptedPart
      .builder()
      .beacon(severityBeacon)
      .prefix("S-")
      .build();
    EncryptedPart buildingPart = EncryptedPart
      .builder()
      .beacon(buildingBeacon)
      .prefix("B-")
      .build();
    EncryptedPart floorPart = EncryptedPart
      .builder()
      .beacon(floorBeacon)
      .prefix("F-")
      .build();
    EncryptedPart roomPart = EncryptedPart
      .builder()
      .beacon(roomBeacon)
      .prefix("R-")
      .build();
    EncryptedPart deskPart = EncryptedPart
      .builder()
      .beacon(deskBeacon)
      .prefix("D-")
      .build();

    // Signed parts
    // These are unencrypted attributes we would like to use in beacon queries.
    // In this example, all of these represent dates or times.
    // Keeping these attributes unencrypted allows us to use them in comparison-based queries.
    // If a signed part is the first part in a compound beacon, then that part can be used in
    // comparison for sorting.
    SignedPart ticketModTimePart = SignedPart
      .builder()
      .name("TicketModTime")
      .prefix("M-")
      .build();
    SignedPart meetingStartPart = SignedPart
      .builder()
      .name("MeetingStart")
      .prefix("MS-")
      .build();
    SignedPart timeCardStartPart = SignedPart
      .builder()
      .name("TimeCardStart")
      .prefix("TC-")
      .build();
    SignedPart projectStartPart = SignedPart
      .builder()
      .name("ProjectStart")
      .prefix("PS-")
      .build();

    // Define constructors
    //    A constructor is one allowed way to assemble a compound beacon value: an ordered list of
    //    the compound beacon's encrypted and signed parts, joined by its separator. Each
    //    CompoundBeaconConstructorPart takes one of those parts and says whether it is required or
    //    optional, and the parts are written in the order they are listed. When an item is
    //    written, the compound beacon's constructors are tried in order, and the first one whose
    //    required parts are all on the item is used; an optional part that is missing is left
    //    out. The constructors below build the PK and SK values for each record type in this
    //    example. All their parts are required.

    // The employee ID constructor only requires an employee ID.
    // If an item has an attribute with name "EmployeeID", it will match this constructor.
    // If this is the first matching constructor in the constructor list (constructor list
    // described more below), the compound beacon will use this constructor, and the compound
    // beacon will be written as `E-X`.
    CompoundBeaconConstructor employeeIdConstructor =
      CompoundBeaconConstructor.of(
        CompoundBeaconConstructorPart.required(employeeIdPart)
      );

    CompoundBeaconConstructor ticketNumberConstructor =
      CompoundBeaconConstructor.of(
        CompoundBeaconConstructorPart.required(ticketNumberPart)
      );

    CompoundBeaconConstructor projectNameConstructor =
      CompoundBeaconConstructor.of(
        CompoundBeaconConstructorPart.required(projectNamePart)
      );

    CompoundBeaconConstructor ticketModTimeConstructor =
      CompoundBeaconConstructor.of(
        CompoundBeaconConstructorPart.required(ticketModTimePart)
      );

    CompoundBeaconConstructor buildingConstructor =
      CompoundBeaconConstructor.of(
        CompoundBeaconConstructorPart.required(buildingPart)
      );

    // This constructor requires all of "MeetingStart", "Location.Floor", and "Location.Room"
    // attributes. If an item has all of these attributes, it will match this constructor.
    // If this is the first matching constructor in the constructor list (constructor list
    // described more below), the compound beacon will use this constructor, and the compound
    // beacon will be written as `MS-X~F-Y~R-Z`.
    // In a constructor with more than one part, the order of the parts defines the order they are
    // written in. Reordering them reorders the beacon value.
    CompoundBeaconConstructor meetingStartFloorRoomConstructor =
      CompoundBeaconConstructor.of(
        CompoundBeaconConstructorPart.required(meetingStartPart),
        CompoundBeaconConstructorPart.required(floorPart),
        CompoundBeaconConstructorPart.required(roomPart)
      );

    CompoundBeaconConstructor timeCardStartEmployeeEmailConstructor =
      CompoundBeaconConstructor.of(
        CompoundBeaconConstructorPart.required(timeCardStartPart),
        CompoundBeaconConstructorPart.required(employeeEmailPart)
      );

    CompoundBeaconConstructor timeCardStartConstructor =
      CompoundBeaconConstructor.of(
        CompoundBeaconConstructorPart.required(timeCardStartPart)
      );

    CompoundBeaconConstructor creatorEmailConstructor =
      CompoundBeaconConstructor.of(
        CompoundBeaconConstructorPart.required(creatorEmailPart)
      );

    CompoundBeaconConstructor projectStatusConstructor =
      CompoundBeaconConstructor.of(
        CompoundBeaconConstructorPart.required(projectStatusPart)
      );

    CompoundBeaconConstructor employeeEmailConstructor =
      CompoundBeaconConstructor.of(
        CompoundBeaconConstructorPart.required(employeeEmailPart)
      );

    CompoundBeaconConstructor organizerEmailConstructor =
      CompoundBeaconConstructor.of(
        CompoundBeaconConstructorPart.required(organizerEmailPart)
      );

    CompoundBeaconConstructor projectStartConstructor =
      CompoundBeaconConstructor.of(
        CompoundBeaconConstructorPart.required(projectStartPart)
      );

    CompoundBeaconConstructor managerEmailConstructor =
      CompoundBeaconConstructor.of(
        CompoundBeaconConstructorPart.required(managerEmailPart)
      );

    CompoundBeaconConstructor assigneeEmailConstructor =
      CompoundBeaconConstructor.of(
        CompoundBeaconConstructorPart.required(assigneeEmailPart)
      );

    CompoundBeaconConstructor cityConstructor = CompoundBeaconConstructor.of(
      CompoundBeaconConstructorPart.required(cityPart)
    );

    CompoundBeaconConstructor severityConstructor =
      CompoundBeaconConstructor.of(
        CompoundBeaconConstructorPart.required(severityPart)
      );

    CompoundBeaconConstructor buildingFloorDeskConstructor =
      CompoundBeaconConstructor.of(
        CompoundBeaconConstructorPart.required(buildingPart),
        CompoundBeaconConstructorPart.required(floorPart),
        CompoundBeaconConstructorPart.required(deskPart)
      );

    // 3. Create BeaconConfig.
    //    The beacon configuration lists every standard beacon, compound beacon, encrypted part
    //    and signed part from step 2.
    BeaconConfig beaconConfig = BeaconConfig
      .builder()
      .standardBeacons(
        employeeIdBeacon,
        ticketNumberBeacon,
        projectNameBeacon,
        employeeEmailBeacon,
        creatorEmailBeacon,
        projectStatusBeacon,
        organizerEmailBeacon,
        managerEmailBeacon,
        assigneeEmailBeacon,
        cityBeacon,
        severityBeacon,
        buildingBeacon,
        floorBeacon,
        roomBeacon,
        deskBeacon
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
      .encryptedParts(
        employeeIdPart,
        ticketNumberPart,
        projectNamePart,
        employeeEmailPart,
        creatorEmailPart,
        projectStatusPart,
        organizerEmailPart,
        managerEmailPart,
        assigneeEmailPart,
        cityPart,
        severityPart,
        buildingPart,
        floorPart,
        roomPart,
        deskPart
      )
      .signedParts(
        ticketModTimePart,
        meetingStartPart,
        timeCardStartPart,
        projectStartPart
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
