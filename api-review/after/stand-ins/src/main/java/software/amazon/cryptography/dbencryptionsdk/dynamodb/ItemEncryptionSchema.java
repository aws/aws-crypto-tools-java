package software.amazon.cryptography.dbencryptionsdk.dynamodb;

public final class ItemEncryptionSchema {
  private ItemEncryptionSchema() {}

  public static Builder builder() { throw Stub.stub(); }

  public static final class Builder {
    private Builder() {}
    public Builder partitionKeyName(String name) { throw Stub.stub(); }
    public Builder sortKeyName(String name) { throw Stub.stub(); }
    public Builder encryptAndSign(String... attributeNames) { throw Stub.stub(); }
    public Builder signOnly(String... attributeNames) { throw Stub.stub(); }
    public Builder doNothingPrefix(String prefix) { throw Stub.stub(); }
    public ItemEncryptionSchema build() { throw Stub.stub(); }
  }
}
