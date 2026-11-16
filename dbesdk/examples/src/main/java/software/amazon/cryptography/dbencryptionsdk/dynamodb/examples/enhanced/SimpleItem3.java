package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.enhanced;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.enhancedclient.DynamoDbEncryptionDoNothing;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.enhancedclient.DynamoDbEncryptionSignOnly;

/**
 * A third item type stored in the same table as {@link SimpleItem} by SingleTableExample. It has
 * different attributes: attribute6 is encrypted and signed, attribute2 is signed only, and
 * ":attribute7" is neither signed nor encrypted.
 */
@DynamoDbBean
public class SimpleItem3 {

  private String partitionKey;
  private int sortKey;
  private String attribute6;
  private String attribute2;
  private String attribute7;

  @DynamoDbPartitionKey
  @DynamoDbAttribute(value = "partition_key")
  public String getPartitionKey() {
    return this.partitionKey;
  }

  public void setPartitionKey(String partitionKey) {
    this.partitionKey = partitionKey;
  }

  @DynamoDbSortKey
  @DynamoDbAttribute(value = "sort_key")
  public int getSortKey() {
    return this.sortKey;
  }

  public void setSortKey(int sortKey) {
    this.sortKey = sortKey;
  }

  public String getAttribute6() {
    return this.attribute6;
  }

  public void setAttribute6(String attribute6) {
    this.attribute6 = attribute6;
  }

  @DynamoDbEncryptionSignOnly
  public String getAttribute2() {
    return this.attribute2;
  }

  public void setAttribute2(String attribute2) {
    this.attribute2 = attribute2;
  }

  @DynamoDbEncryptionDoNothing
  public String getAttribute7() {
    return this.attribute7;
  }

  @DynamoDbAttribute(value = ":attribute7")
  public void setAttribute7(String attribute7) {
    this.attribute7 = attribute7;
  }
}
