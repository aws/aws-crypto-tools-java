// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.primitives.model;

import java.nio.ByteBuffer;
import java.util.Objects;

public class ECCPrivateKey {

  private final ByteBuffer pem;

  protected ECCPrivateKey(BuilderImpl builder) {
    this.pem = builder.pem();
  }

  public ByteBuffer pem() {
    return this.pem;
  }

  public Builder toBuilder() {
    return new BuilderImpl(this);
  }

  public static Builder builder() {
    return new BuilderImpl();
  }

  public interface Builder {
    Builder pem(ByteBuffer pem);

    ByteBuffer pem();

    ECCPrivateKey build();
  }

  static class BuilderImpl implements Builder {

    protected ByteBuffer pem;

    protected BuilderImpl() {}

    protected BuilderImpl(ECCPrivateKey model) {
      this.pem = model.pem();
    }

    public Builder pem(ByteBuffer pem) {
      this.pem = pem;
      return this;
    }

    public ByteBuffer pem() {
      return this.pem;
    }

    public ECCPrivateKey build() {
      if (Objects.isNull(this.pem())) {
        throw new IllegalArgumentException(
          "Missing value for required field `pem`"
        );
      }
      return new ECCPrivateKey(this);
    }
  }
}
