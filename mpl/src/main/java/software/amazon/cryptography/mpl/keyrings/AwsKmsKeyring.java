// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptedDataKey;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnDecryptResponse;
import software.amazon.cryptography.mpl.OnEncryptRequest;
import software.amazon.cryptography.mpl.OnEncryptResponse;
import software.amazon.cryptography.mpl.internal.AwsArnParsing.AwsKmsIdentifier;
import software.amazon.cryptography.mpl.internal.KeyringNames;
import software.amazon.cryptography.mpl.internal.KmsDataKeys;

/**
 * Encrypts and decrypts data keys with one AWS KMS key. Decrypts only data keys encrypted under that exact key.
 * Thread-safe.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/aws-kms/aws-kms-keyring.md">AWS KMS keyring</a>.
 */
//= spec/framework/aws-kms/aws-kms-keyring.md#interface
//= type=implication
//# MUST implement the [AWS Encryption SDK Keyring interface](../keyring-interface.md#interface)
public final class AwsKmsKeyring implements Keyring {

  private final String kmsKeyId;
  private final AwsKmsIdentifier identifier;
  private final KmsClient kmsClient;
  private final List<String> grantTokens;

  private AwsKmsKeyring(String kmsKeyId, AwsKmsIdentifier identifier, KmsClient kmsClient, List<String> grantTokens) {
    this.kmsKeyId = kmsKeyId;
    this.identifier = identifier;
    this.kmsClient = kmsClient;
    this.grantTokens = grantTokens;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** The KMS key: key ARN, key id, alias ARN, or alias name. Decryption needs a key ARN. */
  public String kmsKeyId() {
    return kmsKeyId;
  }

  /** Client in the key's Region. Not closed by the keyring. */
  public KmsClient kmsClient() {
    return kmsClient;
  }

  /** Grant tokens sent with every KMS call. */
  public List<String> grantTokens() {
    return grantTokens;
  }

  @Override
  //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
  //= type=implication
  //# OnEncrypt MUST take [encryption materials]
  //# (../structures.md#encryption-materials) as input.
  public OnEncryptResponse onEncrypt(OnEncryptRequest request) {
    EncryptionMaterials materials = request.materials();
    return OnEncryptResponse.builder().materials(KmsDataKeys.onEncrypt(kmsClient, kmsKeyId, grantTokens, materials)).build();
  }

  /**
   * {@inheritDoc}
   *
   * <p>Fails unless {@link #kmsKeyId()} is a key ARN. Tries each {@code aws-kms} encrypted data key whose provider info
   * is exactly that ARN; one whose provider info is not a KMS ARN fails the whole call.
   */
  @Override
  //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
  //= type=implication
  //# OnDecrypt MUST take [decryption materials]
  //# (../structures.md#decryption-materials) and a list of [encrypted data
  //# keys](../structures.md#encrypted-data-key) as input.
  public OnDecryptResponse onDecrypt(OnDecryptRequest request) {
    DecryptionMaterials materials = request.materials();
    List<EncryptedDataKey> encryptedDataKeys = request.encryptedDataKeys();
    //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
    //= type=implication
    //# If the [decryption materials](../structures.md#decryption-materials)
    //# already contained a valid plaintext data key OnDecrypt MUST return an
    //# error.
    KmsDataKeys.requireNoPlaintextDataKey(materials);
    KmsDataKeys.requireKeyArn(identifier, kmsKeyId);
    List<EncryptedDataKey> candidates = new ArrayList<>();
    //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
    //# The set of encrypted data keys MUST first be filtered to match this
    //#  keyring’s configuration.
    for (EncryptedDataKey edk : encryptedDataKeys) {
      //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
      //= type=implication
      //# - Its provider ID MUST exactly match the value “aws-kms”.
      //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
      //# - The provider info MUST be a [valid AWS KMS ARN](aws-kms-key-
      //# arn.md#a-valid-aws-kms-arn) with a resource type of `key` or
      //# OnDecrypt MUST fail.
      //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
      //# - The provider info MUST match the configured AWS KMS key
      //# identifier.
      if (edk.keyProviderId().equals(KmsDataKeys.PROVIDER_ID) && KmsDataKeys.providerInfoArn(edk).toString().equals(kmsKeyId)) {
        candidates.add(edk);
      }
    }
    return OnDecryptResponse.builder().materials(KmsDataKeys.firstSuccess(
        candidates,
        edk -> KmsDataKeys.decrypt(kmsClient, kmsKeyId, grantTokens, materials, edk),
        encryptedDataKeys,
        materials.algorithmSuite()
      )).build();
  }

  /**
   * Not thread-safe.
   * Requires {@code kmsKeyId}, {@code kmsClient}.
   * {@link #build()} throws {@link software.amazon.cryptography.mpl.exceptions.ValidationException} for invalid settings.
   */
  public static final class Builder {

    private String kmsKeyId;
    private KmsClient kmsClient;
    private Collection<String> grantTokens;

    private Builder() {}

    /** The KMS key: key ARN, key id, alias ARN, or alias name. Decryption needs a key ARN. */
    public Builder kmsKeyId(String kmsKeyId) {
      this.kmsKeyId = kmsKeyId;
      return this;
    }

    /** Client in the key's Region. Not closed by the keyring. */
    public Builder kmsClient(KmsClient kmsClient) {
      this.kmsClient = kmsClient;
      return this;
    }

    public Builder grantTokens(Collection<String> grantTokens) {
      this.grantTokens = grantTokens;
      return this;
    }

    /** The same as {@link #grantTokens(Collection)}; a null array is a null collection. */
    public Builder grantTokens(String... grantTokens) {
      return grantTokens(grantTokens == null ? null : Arrays.asList(grantTokens));
    }

    public AwsKmsKeyring build() {
      //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
      //= type=implication
      //# - MUST provide an AWS KMS key identifier
      KeyringNames.requireSet(kmsKeyId, "kmsKeyId");
      //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
      //= type=implication
      //# - MUST provide an AWS KMS SDK client
      //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
      //= type=implication
      //# The AWS KMS SDK client MUST NOT be null.
      KeyringNames.requireSet(kmsClient, "kmsClient");
      //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
      //= type=implication
      //# The AWS KMS key identifier MUST NOT be null or empty.
      //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
      //= type=implication
      //# The AWS KMS
      //# key identifier MUST be [a valid identifier](aws-kms-key-arn.md#a-
      //# valid-aws-kms-identifier).
      AwsKmsIdentifier identifier = AwsKmsIdentifier.validateKeyId(kmsKeyId);
      //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
      //= type=implication
      //# - MAY provide a list of Grant Tokens
      return new AwsKmsKeyring(kmsKeyId, identifier, kmsClient, KmsDataKeys.grantTokens(grantTokens));
    }
  }
}
