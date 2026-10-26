// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders.model;

import java.util.Objects;
import software.amazon.cryptography.oldapi.materialproviders.IKeyring;
import software.amazon.cryptography.oldapi.materialproviders.Keyring;

/**
 * Inputs for creating a Default Cryptographic Materials Manager.
 */
public class CreateDefaultCryptographicMaterialsManagerInput {

  /**
   * The Keyring that the created Default Cryptographic Materials Manager will use to wrap data keys.
   */
  private final IKeyring keyring;

  protected CreateDefaultCryptographicMaterialsManagerInput(
    BuilderImpl builder
  ) {
    this.keyring = builder.keyring();
  }

  /**
   * @return The Keyring that the created Default Cryptographic Materials Manager will use to wrap data keys.
   */
  public IKeyring keyring() {
    return this.keyring;
  }

  public Builder toBuilder() {
    return new BuilderImpl(this);
  }

  public static Builder builder() {
    return new BuilderImpl();
  }

  public interface Builder {
    /**
     * @param keyring The Keyring that the created Default Cryptographic Materials Manager will use to wrap data keys.
     */
    Builder keyring(IKeyring keyring);

    /**
     * @return The Keyring that the created Default Cryptographic Materials Manager will use to wrap data keys.
     */
    IKeyring keyring();

    CreateDefaultCryptographicMaterialsManagerInput build();
  }

  static class BuilderImpl implements Builder {

    protected IKeyring keyring;

    protected BuilderImpl() {}

    protected BuilderImpl(
      CreateDefaultCryptographicMaterialsManagerInput model
    ) {
      this.keyring = model.keyring();
    }

    public Builder keyring(IKeyring keyring) {
      this.keyring = Keyring.wrap(keyring);
      return this;
    }

    public IKeyring keyring() {
      return this.keyring;
    }

    public CreateDefaultCryptographicMaterialsManagerInput build() {
      if (Objects.isNull(this.keyring())) {
        throw new IllegalArgumentException(
          "Missing value for required field `keyring`"
        );
      }
      return new CreateDefaultCryptographicMaterialsManagerInput(this);
    }
  }
}
