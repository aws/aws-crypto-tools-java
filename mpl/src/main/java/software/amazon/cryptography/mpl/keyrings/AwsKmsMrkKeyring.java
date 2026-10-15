// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptedDataKey;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnEncryptRequest;
import software.amazon.cryptography.mpl.internal.AwsArnParsing.AwsKmsIdentifier;
import software.amazon.cryptography.mpl.internal.KeyringNames;
import software.amazon.cryptography.mpl.internal.KmsDataKeys;

/**
 * Like {@link AwsKmsKeyring}, but treats replicas of a multi-Region key as the same key when decrypting.
 * Thread-safe.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/aws-kms/aws-kms-mrk-keyring.md">AWS KMS MRK keyring</a>.
 */
//= spec/framework/aws-kms/aws-kms-mrk-keyring.md#interface
//= type=implication
//# MUST implement the [AWS Encryption SDK Keyring interface](../keyring-interface.md#interface)
public final class AwsKmsMrkKeyring implements Keyring {

  private final String kmsKeyId;
  private final AwsKmsIdentifier identifier;
  private final KmsClient kmsClient;
  private final List<String> grantTokens;

  private AwsKmsMrkKeyring(String kmsKeyId, AwsKmsIdentifier identifier, KmsClient kmsClient, List<String> grantTokens) {
    this.kmsKeyId = kmsKeyId;
    this.identifier = identifier;
    this.kmsClient = kmsClient;
    this.grantTokens = grantTokens;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** The KMS key, usually a multi-Region key ARN. */
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
  //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
  //= type=implication
  //# OnEncrypt MUST take [encryption materials](../structures.md#encryption-
  //# materials) as input.
  public EncryptionMaterials onEncrypt(OnEncryptRequest request) {
    EncryptionMaterials materials = request.materials();
    return KmsDataKeys.onEncrypt(kmsClient, kmsKeyId, grantTokens, materials);
  }

  /**
   * {@inheritDoc}
   *
   * <p>Fails unless {@link #kmsKeyId()} is a key ARN. Tries each {@code aws-kms} encrypted data key whose provider info
   * is that ARN or, for a multi-Region key, the ARN of a replica; one whose provider info is not a KMS ARN fails the whole call.
   * Decrypt names {@link #kmsKeyId()}, so a replica's data key is decrypted in this keyring's Region.
   */
  @Override
  //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#ondecrypt
  //= type=implication
  //# OnDecrypt MUST take [decryption materials](../structures.md#decryption-
  //# materials) and a list of [encrypted data keys]
  //# (../structures.md#encrypted-data-key) as input.
  public DecryptionMaterials onDecrypt(OnDecryptRequest request) {
    DecryptionMaterials materials = request.materials();
    List<EncryptedDataKey> encryptedDataKeys = request.encryptedDataKeys();
    KmsDataKeys.requireNoPlaintextDataKey(materials);
    KmsDataKeys.requireKeyArn(identifier, kmsKeyId);
    List<EncryptedDataKey> candidates = new ArrayList<>();
    //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#ondecrypt
    //# The set of encrypted data keys MUST first be filtered to match this
    //# keyring’s configuration.
    for (EncryptedDataKey edk : encryptedDataKeys) {
      //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#ondecrypt
      //= type=implication
      //# -  Its provider ID MUST exactly match the value “aws-kms”.
      //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#ondecrypt
      //# -  The provider info MUST be a [valid AWS KMS ARN](aws-kms-key-
      //# arn.md#a-valid-aws-kms-arn) with a resource type of `key` or
      //# OnDecrypt MUST fail.
      //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#ondecrypt
      //# -  The the function [AWS KMS MRK Match for Decrypt](aws-kms-mrk-match-
      //# for-decrypt.md#implementation) called with the configured AWS KMS
      //# key identifier and the provider info MUST return `true`.
      if (edk.keyProviderId().equals(KmsDataKeys.PROVIDER_ID) && identifier.mrkMatches(KmsDataKeys.providerInfoArn(edk))) {
        candidates.add(edk);
      }
    }
    return KmsDataKeys.firstSuccess(
      candidates,
      edk -> KmsDataKeys.decrypt(kmsClient, kmsKeyId, grantTokens, materials, edk),
      encryptedDataKeys,
      materials.algorithmSuite()
    );
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

    /** The KMS key, usually a multi-Region key ARN. */
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

    public AwsKmsMrkKeyring build() {
      KeyringNames.requireSet(kmsKeyId, "kmsKeyId");
      //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#initialization
      //= type=implication
      //# The AWS KMS SDK client MUST NOT be null.
      KeyringNames.requireSet(kmsClient, "kmsClient");
      //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#initialization
      //= type=implication
      //# The AWS KMS key identifier MUST NOT be null or empty.
      //# The AWS KMS
      //# key identifier MUST be [a valid identifier](aws-kms-key-arn.md#a-
      //# valid-aws-kms-identifier).
      AwsKmsIdentifier identifier = AwsKmsIdentifier.validateKeyId(kmsKeyId);
      return new AwsKmsMrkKeyring(kmsKeyId, identifier, kmsClient, KmsDataKeys.grantTokens(grantTokens));
    }
  }
}
