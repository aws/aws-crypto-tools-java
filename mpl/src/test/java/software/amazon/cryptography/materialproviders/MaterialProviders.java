// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;
import software.amazon.cryptography.materialproviders.internal.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.internal.Boundary;
import software.amazon.cryptography.materialproviders.internal.Buffers;
import software.amazon.cryptography.materialproviders.internal.CommitmentPolicies;
import software.amazon.cryptography.materialproviders.internal.CustomCmm;
import software.amazon.cryptography.materialproviders.internal.CustomKeyring;
import software.amazon.cryptography.materialproviders.internal.Errors;
import software.amazon.cryptography.materialproviders.internal.Materials;
import software.amazon.cryptography.materialproviders.internal.NativeCmm;
import software.amazon.cryptography.materialproviders.internal.NativeKeyring;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteInfo;
import software.amazon.cryptography.materialproviders.model.AwsCryptographicMaterialProvidersException;
import software.amazon.cryptography.materialproviders.model.CreateMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRawAesKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRawRsaKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRequiredEncryptionContextCMMInput;
import software.amazon.cryptography.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.model.InitializeDecryptionMaterialsInput;
import software.amazon.cryptography.materialproviders.model.InitializeEncryptionMaterialsInput;
import software.amazon.cryptography.materialproviders.model.InvalidAlgorithmSuiteInfo;
import software.amazon.cryptography.materialproviders.model.InvalidAlgorithmSuiteInfoOnDecrypt;
import software.amazon.cryptography.materialproviders.model.InvalidAlgorithmSuiteInfoOnEncrypt;
import software.amazon.cryptography.materialproviders.model.InvalidDecryptionMaterials;
import software.amazon.cryptography.materialproviders.model.InvalidDecryptionMaterialsTransition;
import software.amazon.cryptography.materialproviders.model.InvalidEncryptionMaterialsTransition;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;
import software.amazon.cryptography.materialproviders.model.ValidDecryptionMaterialsTransitionInput;
import software.amazon.cryptography.materialproviders.model.ValidEncryptionMaterialsTransitionInput;
import software.amazon.cryptography.materialproviders.model.ValidateCommitmentPolicyOnDecryptInput;
import software.amazon.cryptography.materialproviders.model.ValidateCommitmentPolicyOnEncryptInput;
import software.amazon.cryptography.mpl.SecretBytes;
import software.amazon.cryptography.mpl.cmm.RequiredEncryptionContextCryptographicMaterialsManager;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.keyrings.MultiKeyring;
import software.amazon.cryptography.mpl.keyrings.RawAesKeyring;
import software.amazon.cryptography.mpl.keyrings.RawRsaKeyring;

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

  /**
   * Starts encryption materials for a suite: no data key yet, and the verification key,
   * for a signing suite, added to the encryption context under {@code aws-crypto-public-key}.
   */
  public EncryptionMaterials InitializeEncryptionMaterials(
    InitializeEncryptionMaterialsInput input
  ) {
    return Materials.initializeEncryptionMaterials(input);
  }

  /**
   * Starts decryption materials for a suite: no data key yet, and the verification key,
   * for a signing suite, decoded from the encryption context.
   */
  public DecryptionMaterials InitializeDecryptionMaterials(
    InitializeDecryptionMaterialsInput input
  ) {
    return Materials.initializeDecryptionMaterials(input);
  }

  /**
   * Checks that {@code stop} can follow {@code start}: both valid, nothing changed or removed,
   * a plaintext data key present, and encrypted data keys only added.
   *
   * @throws InvalidEncryptionMaterialsTransition if not
   */
  public void ValidEncryptionMaterialsTransition(
    ValidEncryptionMaterialsTransitionInput input
  ) {
    if (!Materials.validEncryptionMaterialsTransition(input.start(), input.stop())) {
      throw InvalidEncryptionMaterialsTransition.builder().message("Invalid Encryption Materials Transition").build();
    }
  }

  /**
   * Checks that {@code stop} is {@code start} with its plaintext data key added.
   *
   * @throws InvalidDecryptionMaterialsTransition if not
   */
  public void ValidDecryptionMaterialsTransition(
    ValidDecryptionMaterialsTransitionInput input
  ) {
    if (!Materials.validDecryptionMaterialsTransition(input.start(), input.stop())) {
      throw InvalidDecryptionMaterialsTransition.builder().message("Invalid Decryption Materials Transition").build();
    }
  }

  /**
   * Checks that the materials are valid and ready to encrypt: a plaintext data key and at least one encrypted data key.
   *
   * @throws InvalidDecryptionMaterials if not
   */
  public void EncryptionMaterialsHasPlaintextDataKey(EncryptionMaterials input) {
    if (!Materials.encryptionMaterialsHasPlaintextDataKey(input)) {
      throw InvalidDecryptionMaterials.builder().message("Invalid Encryption Materials").build();
    }
  }

  /**
   * Checks that the materials are valid and hold a plaintext data key.
   *
   * @throws InvalidDecryptionMaterials if not
   */
  public void DecryptionMaterialsWithPlaintextDataKey(DecryptionMaterials input) {
    if (!Materials.decryptionMaterialsWithPlaintextDataKey(input)) {
      throw InvalidDecryptionMaterials.builder().message("Invalid Decryption Materials").build();
    }
  }

  public IKeyring CreateRawAesKeyring(CreateRawAesKeyringInput input) {
    try {
      return new NativeKeyring(
        RawAesKeyring
          .builder()
          .keyNamespace(input.keyNamespace())
          .keyName(input.keyName())
          .wrappingKey(SecretBytes.copyOf(Buffers.toArray(input.wrappingKey())))
          .wrappingAlg(software.amazon.cryptography.mpl.keyrings.AesWrappingAlg.valueOf(input.wrappingAlg().name()))
          .build()
      );
    } catch (RuntimeException e) {
      throw Errors.toOld(e);
    }
  }

  public IKeyring CreateRawRsaKeyring(CreateRawRsaKeyringInput input) {
    try {
      return new NativeKeyring(
        RawRsaKeyring
          .builder()
          .keyNamespace(input.keyNamespace())
          .keyName(input.keyName())
          .paddingScheme(software.amazon.cryptography.mpl.keyrings.PaddingScheme.valueOf(input.paddingScheme().name()))
          .publicKey(input.publicKey() == null ? null : Buffers.toArray(input.publicKey()))
          .privateKey(input.privateKey() == null ? null : SecretBytes.copyOf(Buffers.toArray(input.privateKey())))
          .build()
      );
    } catch (RuntimeException e) {
      throw Errors.toOld(e);
    }
  }

  public IKeyring CreateMultiKeyring(CreateMultiKeyringInput input) {
    List<software.amazon.cryptography.mpl.Keyring> children = new ArrayList<>();
    for (IKeyring child : input.childKeyrings()) {
      children.add(CustomKeyring.of(child));
    }
    try {
      return new NativeKeyring(
        MultiKeyring
          .builder()
          .generator(input.generator() == null ? null : CustomKeyring.of(input.generator()))
          .childKeyrings(children)
          .build()
      );
    } catch (RuntimeException e) {
      throw Errors.toOld(e);
    }
  }

  public ICryptographicMaterialsManager CreateRequiredEncryptionContextCMM(CreateRequiredEncryptionContextCMMInput input) {
    Boundary.utf8List(input.requiredEncryptionContextKeys());
    try {
      if (input.keyring() != null) {
        throw new ValidationException("CreateRequiredEncryptionContextCMM currently only supports cmm.");
      }
      return new NativeCmm(
        RequiredEncryptionContextCryptographicMaterialsManager
          .builder()
          .underlyingCmm(input.underlyingCMM() == null ? null : CustomCmm.of(input.underlyingCMM()))
          .requiredEncryptionContextKeys(input.requiredEncryptionContextKeys())
          .build()
      );
    } catch (RuntimeException e) {
      throw Errors.toOld(e);
    }
  }

  private static IKeyring create(Supplier<software.amazon.cryptography.mpl.Keyring> build) {
    try {
      return new NativeKeyring(build.get());
    } catch (RuntimeException e) {
      throw Errors.toOld(e);
    }
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
