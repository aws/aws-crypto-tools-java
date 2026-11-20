package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.searchableencryption.complexexample;

import java.util.List;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.ExampleUtils;

/**
 * This file is used in an example to demonstrate complex queries you can perform using beacons. The
 * example data used is for demonstrative purposes only, and might not meet the distribution and
 * correlation uniqueness recommendations for beacons. See our documentation for whether beacons are
 * right for your particular data set:
 * https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/searchable-encryption.html#are-beacons-right-for-me
 *
 * <p>This class implements PutItem calls to populate a DynamoDB table with the example's items. By
 * providing a DynamoDbClient that is configured to use searchable encryption, this class will
 * encrypt the data client side and add beacon attributes to the items. It writes a few items of
 * each of the 6 record types: meetings, employees, projects, reservations, tickets and timecards.
 */
public final class PutRequests {

  private PutRequests() {}

  public static void putAllItemsToTable(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    putAllMeetingItemsToTable(tableName, dynamoDbClient);
    putAllEmployeeItemsToTable(tableName, dynamoDbClient);
    putAllProjectItemsToTable(tableName, dynamoDbClient);
    putAllReservationItemsToTable(tableName, dynamoDbClient);
    putAllTicketItemsToTable(tableName, dynamoDbClient);
    putAllTimecardItemsToTable(tableName, dynamoDbClient);
  }

  private static void putAllMeetingItemsToTable(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    List<AttributeValue> meeting1AttendeeList = List.of(
      AttributeValue.fromS("able@gmail.com"),
      AttributeValue.fromS("zorro@gmail.com")
    );

    Map<String, AttributeValue> meeting1Location = Map.of(
      "Floor",
      AttributeValue.fromS("12"),
      "Room",
      AttributeValue.fromS("403")
    );
    Map<String, AttributeValue> meeting1 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("meeting1")),
      "EmployeeID",
      AttributeValue.fromS("emp_001"),
      "EmployeeEmail",
      AttributeValue.fromS("able@gmail.com"),
      "MeetingStart",
      AttributeValue.fromS("2022-07-04T13:00"),
      "Location",
      AttributeValue.fromM(meeting1Location),
      "Duration",
      AttributeValue.fromS("30"),
      "Attendees",
      AttributeValue.fromL(meeting1AttendeeList),
      "Subject",
      AttributeValue.fromS("Scan Beacons")
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(meeting1).build()
    );

    List<AttributeValue> meeting2AttendeeList = List.of(
      AttributeValue.fromS("barney@gmail.com"),
      AttributeValue.fromS("zorro@gmail.com")
    );

    Map<String, AttributeValue> meeting2Location = Map.of(
      "Floor",
      AttributeValue.fromS("12"),
      "Room",
      AttributeValue.fromS("403")
    );
    Map<String, AttributeValue> meeting2 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("meeting2")),
      "EmployeeID",
      AttributeValue.fromS("emp_002"),
      "EmployeeEmail",
      AttributeValue.fromS("barney@gmail.com"),
      "MeetingStart",
      AttributeValue.fromS("2022-07-04T13:00"),
      "Location",
      AttributeValue.fromM(meeting2Location),
      "Duration",
      AttributeValue.fromS("30"),
      "Attendees",
      AttributeValue.fromL(meeting2AttendeeList),
      "Subject",
      AttributeValue.fromS("Scan Beacons")
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(meeting2).build()
    );

    List<AttributeValue> meeting3AttendeeList = List.of(
      AttributeValue.fromS("charlie@gmail.com"),
      AttributeValue.fromS("zorro@gmail.com")
    );

    Map<String, AttributeValue> meeting3Location = Map.of(
      "Floor",
      AttributeValue.fromS("12"),
      "Room",
      AttributeValue.fromS("403")
    );
    Map<String, AttributeValue> meeting3 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("meeting3")),
      "EmployeeID",
      AttributeValue.fromS("emp_003"),
      "EmployeeEmail",
      AttributeValue.fromS("charlie@gmail.com"),
      "MeetingStart",
      AttributeValue.fromS("2022-07-04T13:00"),
      "Location",
      AttributeValue.fromM(meeting3Location),
      "Duration",
      AttributeValue.fromS("30"),
      "Attendees",
      AttributeValue.fromL(meeting3AttendeeList),
      "Subject",
      AttributeValue.fromS("Scan Beacons")
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(meeting3).build()
    );

    List<AttributeValue> meeting4AttendeeList = List.of(
      AttributeValue.fromS("david@gmail.com"),
      AttributeValue.fromS("zorro@gmail.com")
    );

    Map<String, AttributeValue> meeting4Location = Map.of(
      "Floor",
      AttributeValue.fromS("12"),
      "Room",
      AttributeValue.fromS("403")
    );
    Map<String, AttributeValue> meeting4 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("meeting4")),
      "EmployeeID",
      AttributeValue.fromS("emp_004"),
      "EmployeeEmail",
      AttributeValue.fromS("david@gmail.com"),
      "MeetingStart",
      AttributeValue.fromS("2022-07-04T13:00"),
      "Location",
      AttributeValue.fromM(meeting4Location),
      "Duration",
      AttributeValue.fromS("30"),
      "Attendees",
      AttributeValue.fromL(meeting4AttendeeList),
      "Subject",
      AttributeValue.fromS("Scan Beacons")
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(meeting4).build()
    );

    List<AttributeValue> meeting5AttendeeList = List.of(
      AttributeValue.fromS("barney@gmail.com"),
      AttributeValue.fromS("zorro@gmail.com")
    );

    Map<String, AttributeValue> meeting5Location = Map.of(
      "Floor",
      AttributeValue.fromS("12"),
      "Room",
      AttributeValue.fromS("407")
    );
    Map<String, AttributeValue> meeting5 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("meeting5")),
      "EmployeeID",
      AttributeValue.fromS("emp_002"),
      "EmployeeEmail",
      AttributeValue.fromS("barney@gmail.com"),
      "MeetingStart",
      AttributeValue.fromS("2022-07-04T14:00"),
      "Location",
      AttributeValue.fromM(meeting5Location),
      "Duration",
      AttributeValue.fromS("30"),
      "Attendees",
      AttributeValue.fromL(meeting5AttendeeList),
      "Subject",
      AttributeValue.fromS("DB ESDK")
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(meeting5).build()
    );

    List<AttributeValue> meeting6AttendeeList = List.of(
      AttributeValue.fromS("charlie@gmail.com"),
      AttributeValue.fromS("zorro@gmail.com")
    );

    Map<String, AttributeValue> meeting6Location = Map.of(
      "Floor",
      AttributeValue.fromS("12"),
      "Room",
      AttributeValue.fromS("407")
    );
    Map<String, AttributeValue> meeting6 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("meeting6")),
      "EmployeeID",
      AttributeValue.fromS("emp_003"),
      "EmployeeEmail",
      AttributeValue.fromS("charlie@gmail.com"),
      "MeetingStart",
      AttributeValue.fromS("2022-07-04T14:00"),
      "Location",
      AttributeValue.fromM(meeting6Location),
      "Duration",
      AttributeValue.fromS("30"),
      "Attendees",
      AttributeValue.fromL(meeting6AttendeeList),
      "Subject",
      AttributeValue.fromS("DB ESDK")
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(meeting6).build()
    );
  }

  private static void putAllEmployeeItemsToTable(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    Map<String, AttributeValue> employee1Location = Map.of(
      "Building",
      AttributeValue.fromS("44"),
      "Floor",
      AttributeValue.fromS("12"),
      "Desk",
      AttributeValue.fromS("3"),
      "City",
      AttributeValue.fromS("Seattle")
    );
    Map<String, AttributeValue> employee1 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("employee1")),
      "EmployeeID",
      AttributeValue.fromS("emp_001"),
      "EmployeeEmail",
      AttributeValue.fromS("able@gmail.com"),
      "ManagerEmail",
      AttributeValue.fromS("zorro@gmail.com"),
      "EmployeeName",
      AttributeValue.fromS("Able Jones"),
      "EmployeeTitle",
      AttributeValue.fromS("SDE9"),
      "Location",
      AttributeValue.fromM(employee1Location)
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(employee1).build()
    );

    Map<String, AttributeValue> employee2Location = Map.of(
      "Building",
      AttributeValue.fromS("44"),
      "Floor",
      AttributeValue.fromS("12"),
      "Desk",
      AttributeValue.fromS("4"),
      "City",
      AttributeValue.fromS("Seattle")
    );
    Map<String, AttributeValue> employee2 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("employee2")),
      "EmployeeID",
      AttributeValue.fromS("emp_002"),
      "EmployeeEmail",
      AttributeValue.fromS("barney@gmail.com"),
      "ManagerEmail",
      AttributeValue.fromS("zorro@gmail.com"),
      "EmployeeName",
      AttributeValue.fromS("Barney Jones"),
      "EmployeeTitle",
      AttributeValue.fromS("SDE8"),
      "Location",
      AttributeValue.fromM(employee2Location)
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(employee2).build()
    );

    Map<String, AttributeValue> employee3Location = Map.of(
      "Building",
      AttributeValue.fromS("44"),
      "Floor",
      AttributeValue.fromS("4"),
      "Desk",
      AttributeValue.fromS("5"),
      "City",
      AttributeValue.fromS("Seattle")
    );
    Map<String, AttributeValue> employee3 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("employee3")),
      "EmployeeID",
      AttributeValue.fromS("emp_003"),
      "EmployeeEmail",
      AttributeValue.fromS("charlie@gmail.com"),
      "ManagerEmail",
      AttributeValue.fromS("zorro@gmail.com"),
      "EmployeeName",
      AttributeValue.fromS("Charlie Jones"),
      "EmployeeTitle",
      AttributeValue.fromS("SDE7"),
      "Location",
      AttributeValue.fromM(employee3Location)
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(employee3).build()
    );

    Map<String, AttributeValue> employee4Location = Map.of(
      "Building",
      AttributeValue.fromS("22"),
      "Floor",
      AttributeValue.fromS("1"),
      "Desk",
      AttributeValue.fromS("3"),
      "City",
      AttributeValue.fromS("NYC")
    );
    Map<String, AttributeValue> employee4 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("employee4")),
      "EmployeeID",
      AttributeValue.fromS("emp_004"),
      "EmployeeEmail",
      AttributeValue.fromS("david@gmail.com"),
      "ManagerEmail",
      AttributeValue.fromS("zorro@gmail.com"),
      "EmployeeName",
      AttributeValue.fromS("David Jones"),
      "EmployeeTitle",
      AttributeValue.fromS("SDE6"),
      "Location",
      AttributeValue.fromM(employee4Location)
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(employee4).build()
    );
  }

  private static void putAllProjectItemsToTable(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    Map<String, AttributeValue> project1 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("project1")),
      "ProjectName",
      AttributeValue.fromS("project_001"),
      "ProjectStatus",
      AttributeValue.fromS("Pending"),
      "ProjectStart",
      AttributeValue.fromS("2022-11-01"),
      "Description",
      AttributeValue.fromS("Turbo Crypto"),
      "ProjectTarget",
      AttributeValue.fromS("2024-01-01")
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(project1).build()
    );

    Map<String, AttributeValue> project2 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("project2")),
      "ProjectName",
      AttributeValue.fromS("project_002"),
      "ProjectStatus",
      AttributeValue.fromS("Active"),
      "ProjectStart",
      AttributeValue.fromS("2022-07-04"),
      "Description",
      AttributeValue.fromS("Scan Beacons"),
      "ProjectTarget",
      AttributeValue.fromS("2024-01-01")
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(project2).build()
    );

    Map<String, AttributeValue> project3 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("project3")),
      "ProjectName",
      AttributeValue.fromS("project_003"),
      "ProjectStatus",
      AttributeValue.fromS("Active"),
      "ProjectStart",
      AttributeValue.fromS("2022-08-05"),
      "Description",
      AttributeValue.fromS("DB ESDK"),
      "ProjectTarget",
      AttributeValue.fromS("2023-02-27")
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(project3).build()
    );

    Map<String, AttributeValue> project4 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("project4")),
      "ProjectName",
      AttributeValue.fromS("project_004"),
      "ProjectStatus",
      AttributeValue.fromS("Done"),
      "ProjectStart",
      AttributeValue.fromS("2020-03-03"),
      "Description",
      AttributeValue.fromS("S3EC"),
      "ProjectTarget",
      AttributeValue.fromS("2021-09-05")
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(project4).build()
    );
  }

  private static void putAllReservationItemsToTable(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    List<AttributeValue> reservation1AttendeeList = List.of(
      AttributeValue.fromS("able@gmail.com"),
      AttributeValue.fromS("barney@gmail.com")
    );

    Map<String, AttributeValue> reservation1Location = Map.of(
      "Building",
      AttributeValue.fromS("SEA33"),
      "Floor",
      AttributeValue.fromS("12"),
      "Room",
      AttributeValue.fromS("403")
    );

    Map<String, AttributeValue> reservation1 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("reservation1")),
      "Location",
      AttributeValue.fromM(reservation1Location),
      "MeetingStart",
      AttributeValue.fromS("2022-07-04T13:00"),
      "OrganizerEmail",
      AttributeValue.fromS("able@gmail.com"),
      "Duration",
      AttributeValue.fromS("30"),
      "Attendees",
      AttributeValue.fromL(reservation1AttendeeList),
      "Subject",
      AttributeValue.fromS("Scan beacons")
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(reservation1).build()
    );

    List<AttributeValue> reservation2AttendeeList = List.of(
      AttributeValue.fromS("able@gmail.com"),
      AttributeValue.fromS("barney@gmail.com")
    );

    Map<String, AttributeValue> reservation2Location = Map.of(
      "Building",
      AttributeValue.fromS("SEA33"),
      "Floor",
      AttributeValue.fromS("12"),
      "Room",
      AttributeValue.fromS("407")
    );

    Map<String, AttributeValue> reservation2 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("reservation2")),
      "Location",
      AttributeValue.fromM(reservation2Location),
      "MeetingStart",
      AttributeValue.fromS("2022-07-04T14:00"),
      "OrganizerEmail",
      AttributeValue.fromS("barney@gmail.com"),
      "Duration",
      AttributeValue.fromS("30"),
      "Attendees",
      AttributeValue.fromL(reservation2AttendeeList),
      "Subject",
      AttributeValue.fromS("DB ESDK")
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(reservation2).build()
    );
  }

  private static void putAllTicketItemsToTable(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    Map<String, AttributeValue> ticket1 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("ticket1")),
      "TicketNumber",
      AttributeValue.fromS("ticket_001"),
      "TicketModTime",
      AttributeValue.fromS("2022-10-07T14:32:25"),
      "CreatorEmail",
      AttributeValue.fromS("zorro@gmail.com"),
      "AssigneeEmail",
      AttributeValue.fromS("able@gmail.com"),
      "Severity",
      AttributeValue.fromS("3"),
      "Subject",
      AttributeValue.fromS("Bad bug"),
      "Message",
      AttributeValue.fromS("This bug looks pretty bad")
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(ticket1).build()
    );

    Map<String, AttributeValue> ticket2 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("ticket2")),
      "TicketNumber",
      AttributeValue.fromS("ticket_001"),
      "TicketModTime",
      AttributeValue.fromS("2022-10-07T14:32:25"),
      "CreatorEmail",
      AttributeValue.fromS("able@gmail.com"),
      "AssigneeEmail",
      AttributeValue.fromS("charlie@gmail.com"),
      "Severity",
      AttributeValue.fromS("3"),
      "Subject",
      AttributeValue.fromS("Bad bug"),
      "Message",
      AttributeValue.fromS("Charlie should handle this")
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(ticket2).build()
    );

    Map<String, AttributeValue> ticket3 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("ticket3")),
      "TicketNumber",
      AttributeValue.fromS("ticket_002"),
      "TicketModTime",
      AttributeValue.fromS("2022-10-06T14:32:25"),
      "CreatorEmail",
      AttributeValue.fromS("zorro@gmail.com"),
      "AssigneeEmail",
      AttributeValue.fromS("charlie@gmail.com"),
      "Severity",
      AttributeValue.fromS("3"),
      "Subject",
      AttributeValue.fromS("Easy Bug"),
      "Message",
      AttributeValue.fromS("This seems simple enough")
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(ticket3).build()
    );

    Map<String, AttributeValue> ticket4 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("ticket4")),
      "TicketNumber",
      AttributeValue.fromS("ticket_002"),
      "TicketModTime",
      AttributeValue.fromS("2022-10-08T14:32:25"),
      "CreatorEmail",
      AttributeValue.fromS("charlie@gmail.com"),
      "AssigneeEmail",
      AttributeValue.fromS("able@gmail.com"),
      "Severity",
      AttributeValue.fromS("3"),
      "Subject",
      AttributeValue.fromS("Easy Bug"),
      "Message",
      AttributeValue.fromS("that's in able's code")
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(ticket4).build()
    );
  }

  private static void putAllTimecardItemsToTable(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    Map<String, AttributeValue> timecard1 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("timecard1")),
      "ProjectName",
      AttributeValue.fromS("project_002"),
      "TimeCardStart",
      AttributeValue.fromS("2022-09-12"),
      "EmployeeEmail",
      AttributeValue.fromS("able@gmail.com"),
      "Hours",
      AttributeValue.fromS("40"),
      "Role",
      AttributeValue.fromS("SDE3")
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(timecard1).build()
    );

    Map<String, AttributeValue> timecard2 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("timecard2")),
      "ProjectName",
      AttributeValue.fromS("project_002"),
      "TimeCardStart",
      AttributeValue.fromS("2022-09-12"),
      "EmployeeEmail",
      AttributeValue.fromS("barney@gmail.com"),
      "Hours",
      AttributeValue.fromS("20"),
      "Role",
      AttributeValue.fromS("PM")
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(timecard2).build()
    );

    Map<String, AttributeValue> timecard3 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("timecard3")),
      "ProjectName",
      AttributeValue.fromS("project_003"),
      "TimeCardStart",
      AttributeValue.fromS("2022-09-12"),
      "EmployeeEmail",
      AttributeValue.fromS("charlie@gmail.com"),
      "Hours",
      AttributeValue.fromS("40"),
      "Role",
      AttributeValue.fromS("SDE3")
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(timecard3).build()
    );

    Map<String, AttributeValue> timecard4 = Map.of(
      "partition_key",
      AttributeValue.fromS(ExampleUtils.uniquePartitionKey("timecard4")),
      "ProjectName",
      AttributeValue.fromS("project_003"),
      "TimeCardStart",
      AttributeValue.fromS("2022-09-12"),
      "EmployeeEmail",
      AttributeValue.fromS("barney@gmail.com"),
      "Hours",
      AttributeValue.fromS("20"),
      "Role",
      AttributeValue.fromS("PM")
    );
    dynamoDbClient.putItem(
      PutItemRequest.builder().tableName(tableName).item(timecard4).build()
    );
  }
}
