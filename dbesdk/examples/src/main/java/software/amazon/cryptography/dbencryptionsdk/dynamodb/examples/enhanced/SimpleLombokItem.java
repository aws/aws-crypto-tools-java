package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.enhanced;

import lombok.Builder;
import lombok.Getter;
import lombok.Value;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbImmutable;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.enhancedclient.DynamoDbEncryptionDoNothing;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.enhancedclient.DynamoDbEncryptionSignOnly;

/**
 * An immutable item class for the LombokPutGetExample. Lombok generates the getters and the
 * builder; the Enhanced Client and DB-ESDK annotations are copied onto the generated getters
 * through {@code onMethod_}, because that is where the Enhanced Client reads them.
 */
@Value
@Builder
@DynamoDbImmutable(builder = SimpleLombokItem.SimpleLombokItemBuilder.class)
public class SimpleLombokItem {

  @Getter(
    onMethod_ = {
      @DynamoDbPartitionKey, @DynamoDbAttribute(value = "partition_key"),
    }
  )
  String partitionKey;

  @Getter(
    onMethod_ = { @DynamoDbSortKey, @DynamoDbAttribute(value = "sort_key") }
  )
  int sortKey;

  String attribute1;

  @Getter(onMethod_ = @DynamoDbEncryptionSignOnly)
  String attribute2;

  @Getter(
    onMethod_ = {
      @DynamoDbEncryptionDoNothing, @DynamoDbAttribute(value = ":attribute3"),
    }
  )
  String attribute3;
}
