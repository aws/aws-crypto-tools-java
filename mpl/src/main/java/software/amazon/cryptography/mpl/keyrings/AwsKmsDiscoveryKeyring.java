// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptedDataKey;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnDecryptResponse;
import software.amazon.cryptography.mpl.OnEncryptRequest;
import software.amazon.cryptography.mpl.OnEncryptResponse;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.AwsArnParsing.AwsKmsIdentifier;
import software.amazon.cryptography.mpl.internal.KeyringNames;
import software.amazon.cryptography.mpl.internal.KmsDataKeys;

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

  static final String ENCRYPT_UNSUPPORTED = "Encryption is not supported with a Discovery Keyring.";

  private final KmsClient kmsClient;
  private final DiscoveryFilter discoveryFilter;
  private final List<String> grantTokens;

  private AwsKmsDiscoveryKeyring(KmsClient kmsClient, DiscoveryFilter discoveryFilter, List<String> grantTokens) {
    this.kmsClient = kmsClient;
    this.discoveryFilter = discoveryFilter;
    this.grantTokens = grantTokens;
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
  public OnEncryptResponse onEncrypt(OnEncryptRequest request) {
    EncryptionMaterials materials = request.materials();
    //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#onencrypt
    //= type=implication
    //# This function MUST fail.
    throw new ValidationException(ENCRYPT_UNSUPPORTED);
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
  public OnDecryptResponse onDecrypt(OnDecryptRequest request) {
    DecryptionMaterials materials = request.materials();
    List<EncryptedDataKey> encryptedDataKeys = request.encryptedDataKeys();
    return OnDecryptResponse.builder()
      .materials(decrypt(kmsClient, grantTokens, materials, encryptedDataKeys, arn -> passes(discoveryFilter, arn) ? arn.toString() : null))
      .build();
  }

  //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#ondecrypt
  //# - If a discovery filter is configured, its partition and the provider info partition MUST match.

  //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#ondecrypt
  //# - If a discovery filter is configured, its set of accounts MUST contain the provider info account.

  //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#ondecrypt
  //# - If a discovery filter is configured, its partition and the
  //# provider info partition MUST match.

  //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#ondecrypt
  //# - If a discovery filter is configured, its set of accounts MUST
  //# contain the provider info account.
  static boolean passes(DiscoveryFilter discoveryFilter, AwsKmsIdentifier arn) {
    return discoveryFilter == null || discoveryFilter.matches(arn.partition(), arn.account());
  }

  /**
   * The OnDecrypt of both discovery keyrings.
   * {@code keyIdFor} gives the key id to decrypt an encrypted data key with, or null to skip it.
   */
  static DecryptionMaterials decrypt(
    KmsClient kmsClient,
    List<String> grantTokens,
    DecryptionMaterials materials,
    List<EncryptedDataKey> encryptedDataKeys,
    Function<AwsKmsIdentifier, String> keyIdFor
  ) {
    //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#ondecrypt
    //= type=implication
    //# If the [decryption materials](../structures.md#decryption-materials) already contained a valid plaintext data key,
    //# they keyring MUST fail and MUST NOT modify the [decryption materials](../structures.md#decryption-materials).

    //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#ondecrypt
    //= type=implication
    //# If the [decryption materials](../structures.md#decryption-materials)
    //# already contained a valid plaintext data key, they keyring MUST fail
    //# and MUST NOT modify the [decryption materials]
    //# (../structures.md#decryption-materials).
    KmsDataKeys.requireNoPlaintextDataKey(materials);
    //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#ondecrypt
    //# The set of encrypted data keys MUST first be filtered to match this keyring’s configuration.

    //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#ondecrypt
    //# The set of encrypted data keys MUST first be filtered to match this
    //# keyring’s configuration.
    List<KmsDataKeys.Candidate> candidates = new ArrayList<>();
    for (EncryptedDataKey edk : encryptedDataKeys) {
      //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#ondecrypt
      //# - Its provider ID MUST exactly match the value “aws-kms”.

      //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#ondecrypt
      //# - Its provider ID MUST exactly match the value “aws-kms”.
      if (!edk.keyProviderId().equals(KmsDataKeys.PROVIDER_ID)) {
        continue;
      }
      //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#ondecrypt
      //# - The provider info MUST be a [valid AWS KMS ARN](aws-kms-key
      //# -arn.md#a-valid-aws-kms-arn) with a resource type of `key` or
      //# OnDecrypt MUST fail.

      //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#ondecrypt
      //# - The provider info MUST be a [valid AWS KMS ARN](aws-kms-key-
      //# arn.md#a-valid-aws-kms-arn) with a resource type of `key` or
      //# OnDecrypt MUST fail.
      AwsKmsIdentifier arn = KmsDataKeys.providerInfoArn(edk);
      KmsDataKeys.requireKeyResource(arn);
      String keyId = keyIdFor.apply(arn);
      if (keyId != null) {
        candidates.add(new KmsDataKeys.Candidate(edk, keyId));
      }
    }
    //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#ondecrypt
    //# For each encrypted data key in the filtered set, one at a time, the OnDecrypt MUST attempt to decrypt the data key.

    //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#ondecrypt
    //# For each encrypted data key in the filtered set, one at a time, the
    //# OnDecrypt MUST attempt to decrypt the data key.

    //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#ondecrypt
    //# If the response does not satisfy these requirements
    //# then an error is collected and the next encrypted data key in the filtered set MUST be attempted.

    //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#ondecrypt
    //# If the response does not satisfies these requirements then an error
    //# is collected and the next encrypted data key in the filtered set MUST
    //# be attempted.

    //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#ondecrypt
    //# If OnDecrypt fails to successfully decrypt any [encrypted data key](../structures.md#encrypted-data-key),
    //# then it MUST yield an error that includes all collected errors.

    //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#ondecrypt
    //# If OnDecrypt fails to successfully decrypt any [encrypted data key]
    //# (../structures.md#encrypted-data-key), then it MUST yield an error that
    //# includes all collected errors.
    return KmsDataKeys.firstSuccess(
      candidates,
      //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#ondecrypt
      //= type=implication
      //# To attempt to decrypt a particular [encrypted data key](../structures.md#encrypted-data-key),
      //# OnDecrypt MUST call [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) with the configured AWS KMS client.

      //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#ondecrypt
      //= type=implication
      //# To attempt to decrypt a particular [encrypted data key](../structures.md#encrypted-data-key),
      //# OnDecrypt MUST call [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) with the configured AWS KMS client.
      candidate -> KmsDataKeys.decryptAs(kmsClient, candidate, grantTokens, materials),
      encryptedDataKeys,
      materials.algorithmSuite()
    );
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

    /** Copied; a null collection is the same as an empty one. */
    public Builder grantTokens(Collection<String> grantTokens) {
      this.grantTokens = grantTokens == null ? null : new ArrayList<>(grantTokens);
      return this;
    }

    /** The same as {@link #grantTokens(Collection)} with these values; a null array is passed on as a null collection. */
    public Builder grantTokens(String... grantTokens) {
      return grantTokens(grantTokens == null ? null : Arrays.asList(grantTokens));
    }

    public AwsKmsDiscoveryKeyring build() {
      //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#initialization
      //# The AWS KMS SDK client MUST NOT be null.
      KeyringNames.requireSet(kmsClient, "kmsClient");
      return new AwsKmsDiscoveryKeyring(kmsClient, discoveryFilter, KmsDataKeys.grantTokens(grantTokens));
    }
  }
}
