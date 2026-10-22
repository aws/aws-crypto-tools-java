// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnDecryptResponse;
import software.amazon.cryptography.mpl.OnEncryptRequest;
import software.amazon.cryptography.mpl.OnEncryptResponse;
import software.amazon.cryptography.mpl.internal.KmsDataKeys;
import software.amazon.cryptography.mpl.internal.KmsMultiKeyrings;

/**
 * Discovery keyrings in several Regions, tried in order; cannot encrypt.
 * Thread-safe.
 *
 * <p>Behaves as a {@link MultiKeyring} without a generator whose children are {@link AwsKmsDiscoveryKeyring}s, one per Region,
 * each with the client the client supplier returned for its Region while building.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/aws-kms/aws-kms-multi-keyrings.md">AWS KMS multi-keyrings</a>.
 */
public final class AwsKmsDiscoveryMultiKeyring implements Keyring, AutoCloseable {

  private final List<String> regions;
  private final DiscoveryFilter discoveryFilter;
  private final ClientSupplier clientSupplier;
  private final List<String> grantTokens;
  private final KmsMultiKeyrings.Built built;

  private AwsKmsDiscoveryMultiKeyring(Builder builder, List<String> grantTokens) {
    this.regions = KmsMultiKeyrings.copy(builder.regions);
    this.discoveryFilter = builder.discoveryFilter;
    this.clientSupplier = builder.clientSupplier;
    this.grantTokens = grantTokens;
    this.built = KmsMultiKeyrings.discovery(
      regions,
      clientSupplier,
      //= spec/framework/aws-kms/aws-kms-multi-keyrings.md#aws-kms-discovery-multi-keyring
      //= type=implication
      //# Then a set of [AWS KMS Discovery Keyring](aws-kms-discovery-
      //# keyring.md) MUST be created for each AWS KMS client by initializing
      //# each keyring with
      //# - The AWS KMS client
      //# - The input discovery filter
      //# - The input AWS KMS grant tokens
      (client, region) -> AwsKmsDiscoveryKeyring.builder().kmsClient(client).discoveryFilter(discoveryFilter).grantTokens(grantTokens).build()
    );
  }

  public static Builder builder() {
    return new Builder();
  }

  /** The Regions to decrypt in. At least one. */
  public List<String> regions() {
    return regions;
  }

  /** Limits decryption to KMS keys in these accounts and partition. */
  public Optional<DiscoveryFilter> discoveryFilter() {
    return Optional.ofNullable(discoveryFilter);
  }

  /** Supplies a KMS client per Region; default {@link ClientSupplier#defaultSupplier()}. */
  public Optional<ClientSupplier> clientSupplier() {
    return Optional.ofNullable(clientSupplier);
  }

  /** Grant tokens sent with every KMS call. */
  public List<String> grantTokens() {
    return grantTokens;
  }

  /**
   * Closes the clients of the default client supplier, if this keyring created one; a supplied {@code clientSupplier} is not closed.
   * Optional: it only releases those clients, so a keyring kept for the life of the application needs no close.
   * Do not use the keyring after closing it.
   */
  @Override
  public void close() {
    built.close();
  }

  /** Always throws: discovery keyrings cannot encrypt. */
  @Override
  public OnEncryptResponse onEncrypt(OnEncryptRequest request) {
    return built.keyring.onEncrypt(request);
  }

  @Override
  public OnDecryptResponse onDecrypt(OnDecryptRequest request) {
    return built.keyring.onDecrypt(request);
  }

  /**
   * Not thread-safe.
   * {@link #build()} throws {@link software.amazon.cryptography.mpl.exceptions.ValidationException} for invalid settings.
   */
  //= spec/framework/aws-kms/aws-kms-multi-keyrings.md#aws-kms-discovery-multi-keyring
  //= type=implication
  //# The caller MUST provide:
  //# -  A set of Region strings
  //# -  An optional discovery filter that is an AWS partition and a set of
  //#   AWS accounts
  //# -  An optional method that can take a region string and return an AWS
  //#   KMS client e.g. a regional client supplier
  //# -  An optional list of AWS KMS grant tokens
  public static final class Builder {

    private Collection<String> regions;
    private DiscoveryFilter discoveryFilter;
    private ClientSupplier clientSupplier;
    private Collection<String> grantTokens;

    private Builder() {}

    public Builder regions(Collection<String> regions) {
      this.regions = regions;
      return this;
    }

    /** The same as {@link #regions(Collection)}; a null array is a null collection. */
    public Builder regions(String... regions) {
      return regions(regions == null ? null : Arrays.asList(regions));
    }

    /** Limits decryption to KMS keys in these accounts and partition. */
    public Builder discoveryFilter(DiscoveryFilter discoveryFilter) {
      this.discoveryFilter = discoveryFilter;
      return this;
    }

    /** Supplies a KMS client per Region; default {@link ClientSupplier#defaultSupplier()}. */
    public Builder clientSupplier(ClientSupplier clientSupplier) {
      this.clientSupplier = clientSupplier;
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

    /** Gets each Region's client from the client supplier. */
    public AwsKmsDiscoveryMultiKeyring build() {
      return new AwsKmsDiscoveryMultiKeyring(this, KmsDataKeys.grantTokens(grantTokens));
    }
  }
}
