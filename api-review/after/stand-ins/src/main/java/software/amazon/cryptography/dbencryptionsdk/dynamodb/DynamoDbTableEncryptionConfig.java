package software.amazon.cryptography.dbencryptionsdk.dynamodb;

import software.amazon.cryptography.materialproviders.DbeAlgorithmSuite;
import software.amazon.cryptography.materialproviders.Keyring;

public final class DynamoDbTableEncryptionConfig {
  private DynamoDbTableEncryptionConfig() {}

  public static Builder builder() { throw Stub.stub(); }

  public static final class Builder {
    private Builder() {}
    public Builder tableName(String tableName) { throw Stub.stub(); }
    public Builder logicalTableName(String logicalTableName) { throw Stub.stub(); }
    public Builder schema(ItemEncryptionSchema schema) { throw Stub.stub(); }
    public Builder keyring(Keyring keyring) { throw Stub.stub(); }
    public Builder algorithmSuite(DbeAlgorithmSuite algorithmSuite) { throw Stub.stub(); }
    public DynamoDbTableEncryptionConfig build() { throw Stub.stub(); }
  }
}
