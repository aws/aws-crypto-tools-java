package software.amazon.cryptography.dbencryptionsdk.dynamodb;

import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;

public final class DynamoDbEncryptionInterceptor implements ExecutionInterceptor {
  private DynamoDbEncryptionInterceptor() {}

  public static Builder builder() { throw Stub.stub(); }

  public static final class Builder {
    private Builder() {}
    public Builder tableConfigs(DynamoDbTableEncryptionConfig tableConfigs) { throw Stub.stub(); }
    public DynamoDbEncryptionInterceptor build() { throw Stub.stub(); }
  }
}
