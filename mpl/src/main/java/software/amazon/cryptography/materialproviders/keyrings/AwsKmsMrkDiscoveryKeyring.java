// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keyrings;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnDecryptResponse;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.internal.AwsArnParsing.AwsKmsIdentifier;
import software.amazon.cryptography.materialproviders.internal.KeyringNames;
import software.amazon.cryptography.materialproviders.internal.KmsDataKeys;

/**
 * Discovery keyring for {@code region}: decrypts data keys under single-Region keys in that Region
 * and under multi-Region keys with a replica there; cannot encrypt.
 * Thread-safe.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/aws-kms/aws-kms-mrk-discovery-keyring.md">AWS KMS MRK discovery keyring</a>.
 */
//= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#interface
//= type=implication
//# MUST implement that [AWS Encryption SDK Keyring interface](../keyring-
//# interface.md#interface)
public final class AwsKmsMrkDiscoveryKeyring implements Keyring {

  private final KmsClient kmsClient;
  private final DiscoveryFilter discoveryFilter;
  private final List<String> grantTokens;
  private final String region;

  private AwsKmsMrkDiscoveryKeyring(KmsClient kmsClient, DiscoveryFilter discoveryFilter, List<String> grantTokens, String region) {
    this.kmsClient = kmsClient;
    this.discoveryFilter = discoveryFilter;
    this.grantTokens = grantTokens;
    this.region = region;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Client for {@code region}. Not closed by the keyring. */
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

  /** The Region to decrypt in; replica keys are used through this Region. */
  public String region() {
    return region;
  }

  /** Always throws {@link ValidationException}. */
  @Override
  public OnEncryptResponse onEncrypt(OnEncryptRequest request) {
    EncryptionMaterials materials = request.materials();
    //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#onencrypt
    //= type=implication
    //# This function MUST fail.
    throw new ValidationException(AwsKmsDiscoveryKeyring.ENCRYPT_UNSUPPORTED);
  }

  /**
   * {@inheritDoc}
   *
   * <p>Tries each {@code aws-kms} encrypted data key whose provider info is a key ARN that passes the discovery filter
   * and is either a multi-Region key or in {@link #region()}.
   * KMS decrypts with that ARN, with the Region of a multi-Region key replaced by {@link #region()}.
   * An {@code aws-kms} encrypted data key whose provider info is not a KMS key ARN fails the whole call.
   */
  //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#ondecrypt
  //= type=implication
  //# OnDecrypt MUST take [decryption materials](../structures.md#decryption-
  //# materials) and a list of [encrypted data keys]
  //# (../structures.md#encrypted-data-key) as input.
  @Override
  public OnDecryptResponse onDecrypt(OnDecryptRequest request) {
    DecryptionMaterials materials = request.materials();
    List<EncryptedDataKey> encryptedDataKeys = request.encryptedDataKeys();
    return OnDecryptResponse.builder()
      .materials(AwsKmsDiscoveryKeyring.decrypt(kmsClient, grantTokens, materials, encryptedDataKeys, this::keyIdFor))
      .build();
  }

  // DiscoveryMatch and ToStringForRegion: a single-Region key must be in this Region; a multi-Region key is used through its replica here.
  private String keyIdFor(AwsKmsIdentifier arn) {
    if (!AwsKmsDiscoveryKeyring.passes(discoveryFilter, arn)) {
      return null;
    }
    //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#ondecrypt
    //# - `KeyId`: If the provider info’s resource type is `key` and its
    //# resource is a multi-Region key then a new ARN MUST be created
    //# where the region part MUST equal the AWS KMS client region and
    //# every other part MUST equal the provider info.
    if (arn.isMultiRegion()) {
      return arn.toArnString(region);
    }
    //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#ondecrypt
    //# - If the provider info is not [identified as a multi-Region key](aws-
    //# kms-key-arn.md#identifying-an-aws-kms-multi-region-key), then the
    //# provider info’sRegion MUST match the AWS KMS client region.

    //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#ondecrypt
    //# Otherwise it MUST
    //# be the provider info.
    return arn.region().equals(region) ? arn.toString() : null;
  }

  /**
   * Not thread-safe.
   * Requires {@code kmsClient}, {@code region}.
   * {@link #build()} throws {@link software.amazon.cryptography.materialproviders.exceptions.ValidationException} for invalid settings.
   */
  //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#initialization
  //= type=implication
  //# On initialization the keyring MUST accept the following parameters:

  //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#initialization
  //= type=exception
  //= reason=The Region of a caller-supplied KMS client is not known to the builder, so the configured region is not compared with it.
  //# The keyring SHOULD fail initialization if the provided region does not match the
  //# region of the KMS client.
  public static final class Builder {

    private KmsClient kmsClient;
    private DiscoveryFilter discoveryFilter;
    private Collection<String> grantTokens;
    private String region;

    private Builder() {}

    /** Client for {@code region}. Not closed by the keyring. */
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

    /** The Region to decrypt in; replica keys are used through this Region. */
    public Builder region(String region) {
      this.region = region;
      return this;
    }

    public AwsKmsMrkDiscoveryKeyring build() {
      //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#initialization
      //# They keyring MUST fail initialization if any required parameters are
      //# missing or null.
      KeyringNames.requireSet(kmsClient, "kmsClient");
      KeyringNames.requireSet(region, "region");
      return new AwsKmsMrkDiscoveryKeyring(kmsClient, discoveryFilter, KmsDataKeys.grantTokens(grantTokens), region);
    }
  }
}
