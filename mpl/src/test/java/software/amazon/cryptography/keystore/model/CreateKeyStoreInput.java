// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.keystore.model;

public class CreateKeyStoreInput {

  protected CreateKeyStoreInput(BuilderImpl builder) {}

  public Builder toBuilder() {
    return new BuilderImpl(this);
  }

  public static Builder builder() {
    return new BuilderImpl();
  }

  public interface Builder {
    CreateKeyStoreInput build();
  }

  static class BuilderImpl implements Builder {

    protected BuilderImpl() {}

    protected BuilderImpl(CreateKeyStoreInput model) {}

    public CreateKeyStoreInput build() {
      return new CreateKeyStoreInput(this);
    }
  }
}
