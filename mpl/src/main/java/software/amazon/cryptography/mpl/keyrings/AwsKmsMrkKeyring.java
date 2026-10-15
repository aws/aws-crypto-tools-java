// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import java.util.Collection;
import java.util.List;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnEncryptRequest;

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
  private final KmsClient kmsClient;
  private final List<String> grantTokens;

  private AwsKmsMrkKeyring() {
    throw new UnsupportedOperationException("not implemented yet");
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
    throw new UnsupportedOperationException("not implemented yet");
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
    throw new UnsupportedOperationException("not implemented yet");
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
      throw new UnsupportedOperationException("not implemented yet");
    }
  }
}
