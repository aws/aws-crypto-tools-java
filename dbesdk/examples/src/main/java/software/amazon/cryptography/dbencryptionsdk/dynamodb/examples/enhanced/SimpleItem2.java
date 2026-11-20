package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.enhanced;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.enhancedclient.DynamoDbEncryptionDoNothing;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.enhancedclient.DynamoDbEncryptionSignOnly;

/**
 * A second item type stored in the same table as {@link SimpleItem} by SingleTableExample. It has
 * different attributes: attribute4 is encrypted and signed, attribute5 is signed only, and
 * ":attribute3" is neither signed nor encrypted.
 */
@DynamoDbBean
public class SimpleItem2 {

  private String partitionKey;
  private int sortKey;
  private String attribute4;
  private String attribute5;
  private String attribute3;

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

  public String getAttribute4() {
    return this.attribute4;
  }

  public void setAttribute4(String attribute4) {
    this.attribute4 = attribute4;
  }

  @DynamoDbEncryptionSignOnly
  public String getAttribute5() {
    return this.attribute5;
  }

  public void setAttribute5(String attribute5) {
    this.attribute5 = attribute5;
  }

  @DynamoDbEncryptionDoNothing
  public String getAttribute3() {
    return this.attribute3;
  }

  @DynamoDbAttribute(value = ":attribute3")
  public void setAttribute3(String attribute3) {
    this.attribute3 = attribute3;
  }
}
