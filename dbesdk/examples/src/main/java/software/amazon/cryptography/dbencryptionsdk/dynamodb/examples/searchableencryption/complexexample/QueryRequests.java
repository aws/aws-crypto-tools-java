package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.searchableencryption.complexexample;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryResponse;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.ExampleUtils;

/**
 * This file is used in an example to demonstrate complex queries you can perform using beacons. The
 * example data used is for demonstrative purposes only, and might not meet the distribution and
 * correlation uniqueness recommendations for beacons. See our documentation for whether beacons are
 * right for your particular data set:
 * https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/searchable-encryption.html#are-beacons-right-for-me
 *
 * <p>This class implements the complex example's query access patterns. The queries in this file are more
 * complicated than in other searchable encryption examples, and should demonstrate how one can
 * structure queries on beacons in a broader variety of applications.
 */
public final class QueryRequests {

  private QueryRequests() {}

  public static void runQueries(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    runQuery1(tableName, dynamoDbClient);
    runQuery2(tableName, dynamoDbClient);
    runQuery3(tableName, dynamoDbClient);
    runQuery4(tableName, dynamoDbClient);
    runQuery5(tableName, dynamoDbClient);
    runQuery6(tableName, dynamoDbClient);
    runQuery7(tableName, dynamoDbClient);
    runQuery8(tableName, dynamoDbClient);
    runQuery9(tableName, dynamoDbClient);
    runQuery10(tableName, dynamoDbClient);
    runQuery11(tableName, dynamoDbClient);
    runQuery12(tableName, dynamoDbClient);
    runQuery13(tableName, dynamoDbClient);
    runQuery14(tableName, dynamoDbClient);
    runQuery15(tableName, dynamoDbClient);
    runQuery16(tableName, dynamoDbClient);
    runQuery17(tableName, dynamoDbClient);
    runQuery18(tableName, dynamoDbClient);
    runQuery19(tableName, dynamoDbClient);
    runQuery20(tableName, dynamoDbClient);
    runQuery21(tableName, dynamoDbClient);
    runQuery22(tableName, dynamoDbClient);
    runQuery23(tableName, dynamoDbClient);
  }

  private static void runQuery1(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 1: Get meetings by date and email
    // Key condition: PK1=email SK1 between(date1, date2)
    // Filter condition: duration > 0
    Map<String, String> query1AttributeNames = Map.of(
      "#pk1",
      "PK1",
      "#sk1",
      "SK1",
      "#duration",
      "Duration"
    );
    Map<String, AttributeValue> query1AttributeValues = Map.of(
      ":e",
      AttributeValue.fromS("EE-able@gmail.com"),
      ":date1",
      AttributeValue.fromS("MS-2022-07-02"),
      ":date2",
      AttributeValue.fromS("MS-2022-07-08"),
      ":zero",
      AttributeValue.fromS("0"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query1Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-1")
      .keyConditionExpression("#pk1 = :e AND #sk1 BETWEEN :date1 AND :date2")
      .filterExpression(
        "#duration > :zero AND contains(partition_key, :runSuffix)"
      )
      .expressionAttributeNames(query1AttributeNames)
      .expressionAttributeValues(query1AttributeValues)
      .build();

    QueryResponse query1Response = dynamoDbClient.query(query1Request);

    // Assert 1 item was returned: `meeting1`
    assert query1Response.items().size() == 1;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> meeting1 = itemWithPartitionKey(
      query1Response.items(),
      ExampleUtils.uniquePartitionKey("meeting1")
    );
    assert meeting1.get("Subject").s().equals("Scan Beacons");
    assert meeting1.get("Location").m().get("Floor").s().equals("12");
    assert meeting1
      .get("Attendees")
      .l()
      .contains(AttributeValue.fromS("zorro@gmail.com"));
  }

  private static void runQuery2(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 2: Get meetings by date and employeeID
    // Key condition: PK=employeeID SK between(date1, date2)
    // Filter condition: duration > 0
    Map<String, String> query2AttributeNames = Map.of(
      "#pk",
      "PK",
      "#sk",
      "SK",
      "#duration",
      "Duration"
    );
    Map<String, AttributeValue> query2AttributeValues = Map.of(
      ":employee",
      AttributeValue.fromS("E-emp_001"),
      ":date1",
      AttributeValue.fromS("MS-2022-07-02"),
      ":date2",
      AttributeValue.fromS("MS-2022-07-08"),
      ":zero",
      AttributeValue.fromS("0"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query2Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-0")
      .keyConditionExpression(
        "#pk = :employee AND #sk BETWEEN :date1 AND :date2"
      )
      .filterExpression(
        "#duration > :zero AND contains(partition_key, :runSuffix)"
      )
      .expressionAttributeNames(query2AttributeNames)
      .expressionAttributeValues(query2AttributeValues)
      .build();

    QueryResponse query2Response = dynamoDbClient.query(query2Request);

    // Assert 1 item was returned: `meeting1`
    assert query2Response.items().size() == 1;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> meeting1 = itemWithPartitionKey(
      query2Response.items(),
      ExampleUtils.uniquePartitionKey("meeting1")
    );
    assert meeting1.get("Subject").s().equals("Scan Beacons");
    assert meeting1.get("Location").m().get("Floor").s().equals("12");
    assert meeting1
      .get("Attendees")
      .l()
      .contains(AttributeValue.fromS("zorro@gmail.com"));
  }

  private static void runQuery3(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 3: Get meetings by date and building/floor/room
    // Key condition: PK=employeeID SK between(date1, date2)
    // Filter condition: building, floor and room each equal the given value
    // A filter expression cannot use the primary key attributes, so instead of filtering on
    // "SK contains building.floor.room", this query filters on the individual beacon attributes
    // building, floor and room.
    Map<String, String> query3AttributeNames = Map.of(
      "#pk",
      "PK",
      "#sk",
      "SK",
      "#building",
      "Building",
      "#floor",
      "Floor",
      "#room",
      "Room"
    );
    Map<String, AttributeValue> query3AttributeValues = Map.of(
      ":buildingbeacon",
      AttributeValue.fromS("B-SEA33"),
      ":building",
      AttributeValue.fromS("SEA33"),
      ":floor",
      AttributeValue.fromS("12"),
      ":room",
      AttributeValue.fromS("403"),
      ":date1",
      AttributeValue.fromS("MS-2022-07-02"),
      ":date2",
      AttributeValue.fromS("MS-2022-07-08"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query3Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-0")
      .keyConditionExpression(
        "#pk = :buildingbeacon AND #sk BETWEEN :date1 AND :date2"
      )
      .filterExpression(
        "#building = :building AND #floor = :floor AND #room = :room AND contains(partition_key, :runSuffix)"
      )
      .expressionAttributeNames(query3AttributeNames)
      .expressionAttributeValues(query3AttributeValues)
      .build();

    QueryResponse query3Response = dynamoDbClient.query(query3Request);

    // Assert 1 item was returned: `reservation1`
    assert query3Response.items().size() == 1;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> reservation1 = itemWithPartitionKey(
      query3Response.items(),
      ExampleUtils.uniquePartitionKey("reservation1")
    );
    assert reservation1.get("Subject").s().equals("Scan beacons");
    assert reservation1.get("Location").m().get("Building").s().equals("SEA33");
    assert reservation1
      .get("Attendees")
      .l()
      .contains(AttributeValue.fromS("barney@gmail.com"));
  }

  private static void runQuery4(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 4: Get employee data by email
    // Key condition: PK1=email SK1=employee ID
    Map<String, String> query4AttributeNames = Map.of(
      "#pk1",
      "PK1",
      "#sk1",
      "SK1"
    );
    Map<String, AttributeValue> query4AttributeValues = Map.of(
      ":email",
      AttributeValue.fromS("EE-able@gmail.com"),
      ":employee",
      AttributeValue.fromS("E-emp_001"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query4Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-1")
      .keyConditionExpression("#pk1 = :email AND #sk1 = :employee")
      .filterExpression("contains(partition_key, :runSuffix)")
      .expressionAttributeNames(query4AttributeNames)
      .expressionAttributeValues(query4AttributeValues)
      .build();

    QueryResponse query4Response = dynamoDbClient.query(query4Request);

    // Assert 1 item was returned: `employee1`
    assert query4Response.items().size() == 1;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> employee1 = itemWithPartitionKey(
      query4Response.items(),
      ExampleUtils.uniquePartitionKey("employee1")
    );
    assert employee1.get("EmployeeID").s().equals("emp_001");
    assert employee1.get("Location").m().get("Desk").s().equals("3");
  }

  private static void runQuery5(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 5: Get meetings by email
    // Key condition: PK1=email SK1 > 30 days ago
    Map<String, String> query5AttributeNames = Map.of(
      "#pk1",
      "PK1",
      "#sk1",
      "SK1"
    );
    Map<String, AttributeValue> query5AttributeValues = Map.of(
      ":email",
      AttributeValue.fromS("EE-able@gmail.com"),
      ":thirtydaysago",
      AttributeValue.fromS("MS-2023-03-20"),
      ":prefix",
      AttributeValue.fromS("MS-"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query5Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-1")
      .keyConditionExpression(
        "#pk1 = :email AND #sk1 BETWEEN :prefix AND :thirtydaysago"
      )
      .filterExpression("contains(partition_key, :runSuffix)")
      .expressionAttributeNames(query5AttributeNames)
      .expressionAttributeValues(query5AttributeValues)
      .build();

    QueryResponse query5Response = dynamoDbClient.query(query5Request);

    // Assert 1 item was returned: `meeting1`
    assert query5Response.items().size() == 1;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> meeting1 = itemWithPartitionKey(
      query5Response.items(),
      ExampleUtils.uniquePartitionKey("meeting1")
    );
    assert meeting1.get("Subject").s().equals("Scan Beacons");
    assert meeting1.get("Location").m().get("Floor").s().equals("12");
    assert meeting1
      .get("Attendees")
      .l()
      .contains(AttributeValue.fromS("zorro@gmail.com"));
  }

  private static void runQuery6(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 6: Get tickets by email
    // Key condition: PK1=email SK1 > 30 days ago
    Map<String, String> query6AttributeNames = Map.of(
      "#pk1",
      "PK1",
      "#sk1",
      "SK1"
    );
    Map<String, AttributeValue> query6AttributeValues = Map.of(
      ":creatoremail",
      AttributeValue.fromS("CE-zorro@gmail.com"),
      ":thirtydaysago",
      AttributeValue.fromS("MS-2023-03-20"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query6Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-1")
      .keyConditionExpression("#pk1 = :creatoremail AND #sk1 < :thirtydaysago")
      .filterExpression("contains(partition_key, :runSuffix)")
      .expressionAttributeNames(query6AttributeNames)
      .expressionAttributeValues(query6AttributeValues)
      .build();

    QueryResponse query6Response = dynamoDbClient.query(query6Request);

    // Assert 2 items returned:
    // Expected to be `ticket1` and `ticket3`
    assert query6Response.items().size() == 2;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> ticket1 = itemWithPartitionKey(
      query6Response.items(),
      ExampleUtils.uniquePartitionKey("ticket1")
    );
    assert ticket1.get("TicketNumber").s().equals("ticket_001");
  }

  private static void runQuery7(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 7: Get reservations by email
    // Key condition: PK1=organizeremail SK1 > 30 days ago
    Map<String, String> query7AttributeNames = Map.of(
      "#pk1",
      "PK1",
      "#sk1",
      "SK1"
    );
    Map<String, AttributeValue> query7AttributeValues = Map.of(
      ":organizeremail",
      AttributeValue.fromS("OE-able@gmail.com"),
      ":thirtydaysago",
      AttributeValue.fromS("MS-2023-03-20"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query7Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-1")
      .keyConditionExpression(
        "#pk1 = :organizeremail AND #sk1 < :thirtydaysago"
      )
      .filterExpression("contains(partition_key, :runSuffix)")
      .expressionAttributeNames(query7AttributeNames)
      .expressionAttributeValues(query7AttributeValues)
      .build();

    QueryResponse query7Response = dynamoDbClient.query(query7Request);

    // Assert 1 item was returned: `reservation1`
    assert query7Response.items().size() == 1;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> reservation1 = itemWithPartitionKey(
      query7Response.items(),
      ExampleUtils.uniquePartitionKey("reservation1")
    );
    assert reservation1.get("Subject").s().equals("Scan beacons");
    assert reservation1.get("Location").m().get("Floor").s().equals("12");
    assert reservation1
      .get("Attendees")
      .l()
      .contains(AttributeValue.fromS("barney@gmail.com"));
  }

  private static void runQuery8(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 8: Get time cards by email
    // Key condition: PK1=employeeemail SK1 > 30 days ago
    Map<String, String> query8AttributeNames = Map.of(
      "#pk1",
      "PK1",
      "#sk1",
      "SK1"
    );
    Map<String, AttributeValue> query8AttributeValues = Map.of(
      ":email",
      AttributeValue.fromS("EE-able@gmail.com"),
      ":prefix",
      AttributeValue.fromS("TC-"),
      ":thirtydaysago",
      AttributeValue.fromS("TC-2023-03-20"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query8Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-1")
      .keyConditionExpression(
        "#pk1 = :email AND #sk1 BETWEEN :prefix AND :thirtydaysago"
      )
      .filterExpression("contains(partition_key, :runSuffix)")
      .expressionAttributeNames(query8AttributeNames)
      .expressionAttributeValues(query8AttributeValues)
      .build();

    QueryResponse query8Response = dynamoDbClient.query(query8Request);

    // Assert 1 item was returned: `timecard1`
    assert query8Response.items().size() == 1;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> timecard1 = itemWithPartitionKey(
      query8Response.items(),
      ExampleUtils.uniquePartitionKey("timecard1")
    );
    assert timecard1.get("ProjectName").s().equals("project_002");
  }

  private static void runQuery9(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 9: Get employee info by employee ID
    // Key condition: PK1=employeeID SK starts with "E-"
    Map<String, String> query9AttributeNames = Map.of("#pk", "PK", "#sk", "SK");
    Map<String, AttributeValue> query9AttributeValues = Map.of(
      ":employee",
      AttributeValue.fromS("E-emp_001"),
      ":prefix",
      AttributeValue.fromS("E-"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query9Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-0")
      .keyConditionExpression("#pk = :employee AND begins_with(#sk, :prefix)")
      .filterExpression("contains(partition_key, :runSuffix)")
      .expressionAttributeNames(query9AttributeNames)
      .expressionAttributeValues(query9AttributeValues)
      .build();

    QueryResponse query9Response = dynamoDbClient.query(query9Request);

    // Assert 1 item was returned: `employee1`
    assert query9Response.items().size() == 1;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> employee1 = itemWithPartitionKey(
      query9Response.items(),
      ExampleUtils.uniquePartitionKey("employee1")
    );
    assert employee1.get("EmployeeID").s().equals("emp_001");
  }

  private static void runQuery10(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 10: Get employee info by email
    // Key condition: PK1=email
    // Filter condition: SK starts with "E-"
    Map<String, String> query10AttributeNames = Map.of(
      "#pk1",
      "PK1",
      "#sk1",
      "SK1"
    );
    Map<String, AttributeValue> query10AttributeValues = Map.of(
      ":email",
      AttributeValue.fromS("EE-able@gmail.com"),
      ":prefix",
      AttributeValue.fromS("E-"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query10Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-1")
      .keyConditionExpression("#pk1 = :email AND begins_with(#sk1, :prefix)")
      .filterExpression("contains(partition_key, :runSuffix)")
      .expressionAttributeNames(query10AttributeNames)
      .expressionAttributeValues(query10AttributeValues)
      .build();

    QueryResponse query10Response = dynamoDbClient.query(query10Request);

    // Assert 1 item was returned: `employee1`
    assert query10Response.items().size() == 1;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> employee1 = itemWithPartitionKey(
      query10Response.items(),
      ExampleUtils.uniquePartitionKey("employee1")
    );
    assert employee1.get("EmployeeID").s().equals("emp_001");
  }

  private static void runQuery11(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 11: Get ticket history by ticket number
    // Key condition: PK=TicketNumber
    Map<String, String> query11AttributeNames = Map.of("#pk", "PK");
    Map<String, AttributeValue> query11AttributeValues = Map.of(
      ":ticket",
      AttributeValue.fromS("T-ticket_001"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query11Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-0")
      .keyConditionExpression("#pk = :ticket")
      .filterExpression("contains(partition_key, :runSuffix)")
      .expressionAttributeNames(query11AttributeNames)
      .expressionAttributeValues(query11AttributeValues)
      .build();

    QueryResponse query11Response = dynamoDbClient.query(query11Request);

    // Assert 2 items returned:
    // Expected to be `ticket1` and `ticket2`
    assert query11Response.items().size() == 2;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> ticket1 = itemWithPartitionKey(
      query11Response.items(),
      ExampleUtils.uniquePartitionKey("ticket1")
    );
    assert ticket1.get("TicketNumber").s().equals("ticket_001");
  }

  private static void runQuery12(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 12: Get Ticket History by employee email
    // Key condition: PK1=CreatorEmail
    // Filter condition: PK=TicketNumber
    Map<String, String> query12AttributeNames = Map.of(
      "#pk1",
      "PK1",
      "#pk",
      "PK"
    );
    Map<String, AttributeValue> query12AttributeValues = Map.of(
      ":email",
      AttributeValue.fromS("CE-zorro@gmail.com"),
      ":ticket",
      AttributeValue.fromS("T-ticket_001"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query12Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-1")
      .keyConditionExpression("#pk1 = :email")
      .filterExpression("#pk = :ticket AND contains(partition_key, :runSuffix)")
      .expressionAttributeNames(query12AttributeNames)
      .expressionAttributeValues(query12AttributeValues)
      .build();

    QueryResponse query12Response = dynamoDbClient.query(query12Request);

    // Assert 1 item was returned: `ticket1`
    assert query12Response.items().size() == 1;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> ticket1 = itemWithPartitionKey(
      query12Response.items(),
      ExampleUtils.uniquePartitionKey("ticket1")
    );
    assert ticket1.get("TicketNumber").s().equals("ticket_001");
  }

  private static void runQuery13(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 13: Get ticket history by assignee email
    // Key condition: PK=AssigneeEmail
    // Filter condition: PK=ticketNumber
    Map<String, String> query13AttributeNames = Map.of(
      "#pk2",
      "PK2",
      "#pk",
      "PK"
    );
    Map<String, AttributeValue> query13AttributeValues = Map.of(
      ":assigneeemail",
      AttributeValue.fromS("AE-able@gmail.com"),
      ":ticket",
      AttributeValue.fromS("T-ticket_001"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query13Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-2")
      .keyConditionExpression("#pk2 = :assigneeemail")
      .filterExpression("#pk = :ticket AND contains(partition_key, :runSuffix)")
      .expressionAttributeNames(query13AttributeNames)
      .expressionAttributeValues(query13AttributeValues)
      .build();

    QueryResponse query13Response = dynamoDbClient.query(query13Request);

    // Assert 1 item was returned: `ticket1`
    assert query13Response.items().size() == 1;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> ticket1 = itemWithPartitionKey(
      query13Response.items(),
      ExampleUtils.uniquePartitionKey("ticket1")
    );
    assert ticket1.get("Subject").s().equals("Bad bug");
  }

  private static void runQuery14(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 14: Get employees by city.building.floor.desk
    // Key condition: PK3=city SK3 begins_with(building.floor.desk)
    Map<String, String> query14AttributeNames = Map.of(
      "#pk3",
      "PK3",
      "#sk3",
      "SK3"
    );
    Map<String, AttributeValue> query14AttributeValues = Map.of(
      ":city",
      AttributeValue.fromS("C-Seattle"),
      ":location",
      AttributeValue.fromS("B-44~F-12~D-3"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query14Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-3")
      .keyConditionExpression("#pk3 = :city AND begins_with(#sk3, :location)")
      .filterExpression("contains(partition_key, :runSuffix)")
      .expressionAttributeNames(query14AttributeNames)
      .expressionAttributeValues(query14AttributeValues)
      .build();

    // GSIs do not update instantly
    // so if the results come back empty
    // we retry after a short sleep
    int maxQueryAttempts = 10;
    Duration pollInterval = Duration.ofMillis(20);
    List<Map<String, AttributeValue>> query14Items = List.of();
    for (int attempt = 0; attempt < maxQueryAttempts; attempt++) {
      query14Items = dynamoDbClient.query(query14Request).items();
      if (!query14Items.isEmpty()) {
        break;
      }
      try {
        Thread.sleep(pollInterval.toMillis());
      } catch (InterruptedException exception) {
        Thread.currentThread().interrupt();
        break;
      }
    }

    // Assert 1 item was returned: `employee1`. This also fails if every attempt came back empty.
    assert query14Items.size() == 1;
    // Known value test: assert some properties on one of the items
    Map<String, AttributeValue> employee1 = itemWithPartitionKey(
      query14Items,
      ExampleUtils.uniquePartitionKey("employee1")
    );
    assert employee1.get("EmployeeID").s().equals("emp_001");
    assert employee1.get("Location").m().get("Desk").s().equals("3");
  }

  private static void runQuery15(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 15: Get employees by manager email
    // Key condition: PK2 = ManagerEmail
    Map<String, String> query15AttributeNames = Map.of("#pk2", "PK2");
    Map<String, AttributeValue> query15AttributeValues = Map.of(
      ":manageremail",
      AttributeValue.fromS("ME-zorro@gmail.com"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query15Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-2")
      .keyConditionExpression("#pk2 = :manageremail")
      .filterExpression("contains(partition_key, :runSuffix)")
      .expressionAttributeNames(query15AttributeNames)
      .expressionAttributeValues(query15AttributeValues)
      .build();

    QueryResponse query15Response = dynamoDbClient.query(query15Request);

    // Assert 4 items returned:
    // Expected to be `employee1`, `employee2`, `employee3`, and `employee4`
    assert query15Response.items().size() == 4;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> employee1 = itemWithPartitionKey(
      query15Response.items(),
      ExampleUtils.uniquePartitionKey("employee1")
    );
    assert employee1.get("EmployeeID").s().equals("emp_001");
    assert employee1.get("Location").m().get("Desk").s().equals("3");
  }

  private static void runQuery16(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 16: Get assigned tickets by assignee email
    // Key condition: PK2 = AssigneeEmail
    Map<String, String> query16AttributeNames = Map.of("#pk2", "PK2");
    Map<String, AttributeValue> query16AttributeValues = Map.of(
      ":assigneeemail",
      AttributeValue.fromS("AE-able@gmail.com"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query16Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-2")
      .keyConditionExpression("#pk2 = :assigneeemail")
      .filterExpression("contains(partition_key, :runSuffix)")
      .expressionAttributeNames(query16AttributeNames)
      .expressionAttributeValues(query16AttributeValues)
      .build();

    QueryResponse query16Response = dynamoDbClient.query(query16Request);

    // Assert 2 items returned:
    // Expected to be `ticket1` and `ticket4`
    assert query16Response.items().size() == 2;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> ticket1 = itemWithPartitionKey(
      query16Response.items(),
      ExampleUtils.uniquePartitionKey("ticket1")
    );
    assert ticket1.get("TicketNumber").s().equals("ticket_001");
  }

  private static void runQuery17(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 17: Get tickets updated within the last 24 hours
    // Key condition: PK3 = Severity, SK3 > 24 hours ago
    // (For the sake of this example, we will assume
    //  the date is 2022-10-08T09:30:00, such that "24 hours ago"
    //  is 2022-10-07T09:30:00, and that our sample ticket record
    //  with TicketModTime=2022-10-07T14:32:25 will be returned.)
    Map<String, String> query17AttributeNames = Map.of(
      "#pk3",
      "PK3",
      "#sk3",
      "SK3"
    );
    Map<String, AttributeValue> query17AttributeValues = Map.of(
      ":severity",
      AttributeValue.fromS("S-3"),
      ":yesterday",
      AttributeValue.fromS("M-2022-10-07T09:30:00"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query17Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-3")
      .keyConditionExpression("#pk3 = :severity AND #sk3 > :yesterday")
      .filterExpression("contains(partition_key, :runSuffix)")
      .expressionAttributeNames(query17AttributeNames)
      .expressionAttributeValues(query17AttributeValues)
      .build();

    QueryResponse query17Response = dynamoDbClient.query(query17Request);

    // Assert 3 items returned:
    // Expected to be `ticket1`, `ticket2`, and `ticket4`
    assert query17Response.items().size() == 3;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> ticket1 = itemWithPartitionKey(
      query17Response.items(),
      ExampleUtils.uniquePartitionKey("ticket1")
    );
    assert ticket1.get("TicketNumber").s().equals("ticket_001");
  }

  private static void runQuery18(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 18: Get projects by status, start and target date
    // Key condition: PK1 = Status, SK1 > StartDate
    // Filter condition: TargetDelivery < TargetDate
    Map<String, String> query18AttributeNames = Map.of(
      "#pk1",
      "PK1",
      "#sk1",
      "SK1",
      "#target",
      "ProjectTarget"
    );
    Map<String, AttributeValue> query18AttributeValues = Map.of(
      ":status",
      AttributeValue.fromS("PSts-Pending"),
      ":startdate",
      AttributeValue.fromS("PS-2022-01-01"),
      ":target",
      AttributeValue.fromS("2025-01-01"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query18Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-1")
      .keyConditionExpression("#pk1 = :status AND #sk1 > :startdate")
      .filterExpression(
        "#target < :target AND contains(partition_key, :runSuffix)"
      )
      .expressionAttributeNames(query18AttributeNames)
      .expressionAttributeValues(query18AttributeValues)
      .build();

    QueryResponse query18Response = dynamoDbClient.query(query18Request);

    // Assert 1 item was returned: `project1`
    assert query18Response.items().size() == 1;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> project1 = itemWithPartitionKey(
      query18Response.items(),
      ExampleUtils.uniquePartitionKey("project1")
    );
    assert project1.get("ProjectName").s().equals("project_001");
  }

  private static void runQuery19(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 19: Get projects by name
    // Key condition: PK = ProjectName, SK = ProjectName
    Map<String, String> query19AttributeNames = Map.of(
      "#pk",
      "PK",
      "#sk",
      "SK"
    );
    Map<String, AttributeValue> query19AttributeValues = Map.of(
      ":projectname",
      AttributeValue.fromS("P-project_001"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query19Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-0")
      .keyConditionExpression("#pk = :projectname AND #sk = :projectname")
      .filterExpression("contains(partition_key, :runSuffix)")
      .expressionAttributeNames(query19AttributeNames)
      .expressionAttributeValues(query19AttributeValues)
      .build();

    QueryResponse query19Response = dynamoDbClient.query(query19Request);

    // Assert 1 item was returned: `project1`
    assert query19Response.items().size() == 1;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> project1 = itemWithPartitionKey(
      query19Response.items(),
      ExampleUtils.uniquePartitionKey("project1")
    );
    assert project1.get("ProjectName").s().equals("project_001");
  }

  private static void runQuery20(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 20: Get Project History by date range (against timecard record)
    // Key condition: PK = ProjectName, SK between(date1, date2)
    Map<String, String> query20AttributeNames = Map.of(
      "#pk",
      "PK",
      "#sk",
      "SK"
    );
    Map<String, AttributeValue> query20AttributeValues = Map.of(
      ":projectname",
      AttributeValue.fromS("P-project_002"),
      ":date1",
      AttributeValue.fromS("TC-2022-01-01"),
      ":date2",
      AttributeValue.fromS("TC-2023-01-01"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query20Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-0")
      .keyConditionExpression(
        "#pk = :projectname AND #sk BETWEEN :date1 AND :date2"
      )
      .filterExpression("contains(partition_key, :runSuffix)")
      .expressionAttributeNames(query20AttributeNames)
      .expressionAttributeValues(query20AttributeValues)
      .build();

    QueryResponse query20Response = dynamoDbClient.query(query20Request);

    // Assert 2 items returned:
    // Expected to be `timecard1` and `timecard2`
    assert query20Response.items().size() == 2;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> timecard1 = itemWithPartitionKey(
      query20Response.items(),
      ExampleUtils.uniquePartitionKey("timecard1")
    );
    assert timecard1.get("ProjectName").s().equals("project_002");
  }

  private static void runQuery21(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 21: Get Project History by role
    // Key condition: PK = ProjectName
    // Filter condition: role=rolename
    Map<String, String> query21AttributeNames = Map.of(
      "#pk",
      "PK",
      "#role",
      "Role"
    );
    Map<String, AttributeValue> query21AttributeValues = Map.of(
      ":projectname",
      AttributeValue.fromS("P-project_002"),
      ":role",
      AttributeValue.fromS("SDE3"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query21Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-0")
      .keyConditionExpression("#pk = :projectname")
      .filterExpression("#role = :role AND contains(partition_key, :runSuffix)")
      .expressionAttributeNames(query21AttributeNames)
      .expressionAttributeValues(query21AttributeValues)
      .build();

    QueryResponse query21Response = dynamoDbClient.query(query21Request);

    // Assert 1 item was returned: `timecard1`
    assert query21Response.items().size() == 1;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> timecard1 = itemWithPartitionKey(
      query21Response.items(),
      ExampleUtils.uniquePartitionKey("timecard1")
    );
    assert timecard1.get("ProjectName").s().equals("project_002");
  }

  private static void runQuery22(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 22: Get reservations by building ID
    // Key condition: PK = Building ID
    Map<String, String> query22AttributeNames = Map.of("#pk", "PK");
    Map<String, AttributeValue> query22AttributeValues = Map.of(
      ":building",
      AttributeValue.fromS("B-SEA33"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query22Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-0")
      .keyConditionExpression("#pk = :building")
      .filterExpression("contains(partition_key, :runSuffix)")
      .expressionAttributeNames(query22AttributeNames)
      .expressionAttributeValues(query22AttributeValues)
      .build();

    QueryResponse query22Response = dynamoDbClient.query(query22Request);

    // Assert 2 items returned:
    // Expected to be `reservation1` and `reservation2`
    assert query22Response.items().size() == 2;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> reservation1 = itemWithPartitionKey(
      query22Response.items(),
      ExampleUtils.uniquePartitionKey("reservation1")
    );
    assert reservation1.get("Subject").s().equals("Scan beacons");
  }

  private static void runQuery23(
    String tableName,
    DynamoDbClient dynamoDbClient
  ) {
    // Query 23: Get reservations by building ID and time range
    // Key condition: PK = Building ID, SK between(date1, date2)
    // Filter condition: Duration > 0
    Map<String, String> query23AttributeNames = Map.of(
      "#pk",
      "PK",
      "#sk",
      "SK",
      "#duration",
      "Duration"
    );
    Map<String, AttributeValue> query23AttributeValues = Map.of(
      ":building",
      AttributeValue.fromS("B-SEA33"),
      ":date1",
      AttributeValue.fromS("MS-2022-07-01"),
      ":date2",
      AttributeValue.fromS("MS-2022-07-08"),
      ":zero",
      AttributeValue.fromS("0"),
      ":runSuffix",
      AttributeValue.fromS(ExampleUtils.runSuffix())
    );
    QueryRequest query23Request = QueryRequest
      .builder()
      .tableName(tableName)
      .indexName("GSI-0")
      .keyConditionExpression(
        "#pk = :building AND #sk BETWEEN :date1 AND :date2"
      )
      .filterExpression(
        "#duration > :zero AND contains(partition_key, :runSuffix)"
      )
      .expressionAttributeNames(query23AttributeNames)
      .expressionAttributeValues(query23AttributeValues)
      .build();

    QueryResponse query23Response = dynamoDbClient.query(query23Request);

    // Assert 2 items returned:
    // Expected to be `reservation1` and `reservation2`
    assert query23Response.items().size() == 2;
    // Known value test: Assert some properties on one of the items
    Map<String, AttributeValue> reservation1 = itemWithPartitionKey(
      query23Response.items(),
      ExampleUtils.uniquePartitionKey("reservation1")
    );
    assert reservation1.get("Subject").s().equals("Scan beacons");
  }

  // Returns the item whose partition_key is partitionKey. Every item in this example has its own
  // partition key, so there is at most one. Fails if the query results do not include it.
  private static Map<String, AttributeValue> itemWithPartitionKey(
    List<Map<String, AttributeValue>> items,
    String partitionKey
  ) {
    return items
      .stream()
      .filter(item -> item.get("partition_key").s().equals(partitionKey))
      .findFirst()
      .orElseThrow(() ->
        new AssertionError("No item with partition_key " + partitionKey)
      );
  }
}
