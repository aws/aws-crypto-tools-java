// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnEncryptRequest;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

/**
 * Decrypts data keys encrypted under any KMS key the caller may use in the client's Region; cannot encrypt.
 * Thread-safe.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/aws-kms/aws-kms-discovery-keyring.md">AWS KMS discovery keyring</a>.
 */
//= spec/framework/aws-kms/aws-kms-discovery-keyring.md#interface
//= type=implication
//# MUST implement that [AWS Encryption SDK Keyring interface](../keyring-interface.md#interface)
public final class AwsKmsDiscoveryKeyring implements Keyring {

  private final KmsClient kmsClient;
  private final DiscoveryFilter discoveryFilter;
  private final List<String> grantTokens;

  private AwsKmsDiscoveryKeyring() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Client for the Region to decrypt in. Not closed by the keyring. */
  public KmsClient kmsClient() {
    return kmsClient;
  }

  /** Limits decryption to KMS keys in these accounts and partition. */
  public Optional<DiscoveryFilter> discoveryFilter() {
    return Optional.ofNullable(discoveryFilter);
  }

  /** Grant tokens sent with every KMS call. */
  public List<String> grantTokens() {
    return grantTokens;
  }

  /** Always throws {@link ValidationException}. */
  @Override
  public EncryptionMaterials onEncrypt(OnEncryptRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /**
   * {@inheritDoc}
   *
   * <p>Tries each {@code aws-kms} encrypted data key whose provider info is a key ARN that passes the discovery filter,
   * asking KMS to decrypt with that ARN.
   * An {@code aws-kms} encrypted data key whose provider info is not a KMS key ARN fails the whole call.
   */
  //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#ondecrypt
  //= type=implication
  //# OnDecrypt MUST take [decryption materials](../structures.md#decryption-materials) and
  //# a list of [encrypted data keys](../structures.md#encrypted-data-key) as input.
  @Override
  public DecryptionMaterials onDecrypt(OnDecryptRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /**
   * Not thread-safe.
   * Requires {@code kmsClient}.
   * {@link #build()} throws {@link software.amazon.cryptography.mpl.exceptions.ValidationException} for invalid settings.
   */
  //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#initialization
  //= type=implication
  //# On initialization the caller MUST provide:
  public static final class Builder {

    private KmsClient kmsClient;
    private DiscoveryFilter discoveryFilter;
    private Collection<String> grantTokens;

    private Builder() {}

    /** Client for the Region to decrypt in. Not closed by the keyring. */
    public Builder kmsClient(KmsClient kmsClient) {
      this.kmsClient = kmsClient;
      return this;
    }

    /** Limits decryption to KMS keys in these accounts and partition. */
    public Builder discoveryFilter(DiscoveryFilter discoveryFilter) {
      this.discoveryFilter = discoveryFilter;
      return this;
    }

    public Builder grantTokens(Collection<String> grantTokens) {
      this.grantTokens = grantTokens;
      return this;
    }

    public AwsKmsDiscoveryKeyring build() {
      throw new UnsupportedOperationException("not implemented yet");
    }
  }
}
