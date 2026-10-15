// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import java.nio.ByteBuffer;
import java.util.Objects;
import software.amazon.cryptography.materialproviders.internal.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.internal.Buffers;
import software.amazon.cryptography.materialproviders.internal.CommitmentPolicies;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteInfo;
import software.amazon.cryptography.materialproviders.model.AwsCryptographicMaterialProvidersException;
import software.amazon.cryptography.materialproviders.model.InvalidAlgorithmSuiteInfo;
import software.amazon.cryptography.materialproviders.model.InvalidAlgorithmSuiteInfoOnDecrypt;
import software.amazon.cryptography.materialproviders.model.InvalidAlgorithmSuiteInfoOnEncrypt;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;
import software.amazon.cryptography.materialproviders.model.ValidateCommitmentPolicyOnDecryptInput;
import software.amazon.cryptography.materialproviders.model.ValidateCommitmentPolicyOnEncryptInput;

public class MaterialProviders {

  // MaterialProvidersConfig has no fields; the builder only requires that one is passed.
  protected MaterialProviders(BuilderImpl builder) {}

  public static Builder builder() {
    return new BuilderImpl();
  }

  /**
   * Returns the algorithm suite with the given 2-byte id.
   *
   * @param input the id; bytes {@code [0, limit)} are read, regardless of position
   * @throws software.amazon.cryptography.materialproviders.model.AwsCryptographicMaterialProvidersException
   *   if no supported suite has that id
   */
  public AlgorithmSuiteInfo GetAlgorithmSuiteInfo(ByteBuffer input) {
    return AlgorithmSuite.ofBinaryId(Buffers.toArray(input)).info();
  }

  /**
   * Checks that {@code input} is exactly the description of a supported algorithm suite.
   *
   * @throws InvalidAlgorithmSuiteInfo if any field differs from the suite its id names
   */
  public void ValidAlgorithmSuiteInfo(AlgorithmSuiteInfo input) {
    if (!AlgorithmSuite.isValid(input)) {
      throw InvalidAlgorithmSuiteInfo.builder().message("Invalid AlgorithmSuiteInfo").build();
    }
  }

  /**
   * Checks that the commitment policy allows encrypting with the algorithm suite.
   *
   * @throws InvalidAlgorithmSuiteInfoOnEncrypt if it does not
   */
  public void ValidateCommitmentPolicyOnEncrypt(
    ValidateCommitmentPolicyOnEncryptInput input
  ) {
    CommitmentPolicies.validateOnEncrypt(input.algorithm(), input.commitmentPolicy());
  }

  /**
   * Checks that the commitment policy allows decrypting with the algorithm suite.
   *
   * @throws InvalidAlgorithmSuiteInfoOnDecrypt if it does not
   */
  public void ValidateCommitmentPolicyOnDecrypt(
    ValidateCommitmentPolicyOnDecryptInput input
  ) {
    CommitmentPolicies.validateOnDecrypt(input.algorithm(), input.commitmentPolicy());
  }

  public interface Builder {
    Builder MaterialProvidersConfig(
      MaterialProvidersConfig MaterialProvidersConfig
    );

    MaterialProvidersConfig MaterialProvidersConfig();

    MaterialProviders build();
  }

  static class BuilderImpl implements Builder {

    protected MaterialProvidersConfig MaterialProvidersConfig;

    protected BuilderImpl() {}

    public Builder MaterialProvidersConfig(
      MaterialProvidersConfig MaterialProvidersConfig
    ) {
      this.MaterialProvidersConfig = MaterialProvidersConfig;
      return this;
    }

    public MaterialProvidersConfig MaterialProvidersConfig() {
      return this.MaterialProvidersConfig;
    }

    public MaterialProviders build() {
      if (Objects.isNull(this.MaterialProvidersConfig())) {
        throw new IllegalArgumentException(
          "Missing value for required field `MaterialProvidersConfig`"
        );
      }
      return new MaterialProviders(this);
    }
  }
}
