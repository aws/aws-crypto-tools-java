// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Function;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.AwsArnParsing.AwsKmsIdentifier;
import software.amazon.cryptography.mpl.keyrings.ClientSupplier;
import software.amazon.cryptography.mpl.keyrings.DefaultClientSupplier;
import software.amazon.cryptography.mpl.keyrings.MultiKeyring;

/**
 * Builds the multi keyrings of KMS keyrings, per StrictMultiKeyring.dfy, MrkAwareStrictMultiKeyring.dfy,
 * DiscoveryMultiKeyring.dfy, and MrkAwareDiscoveryMultiKeyring.dfy.
 * Clients come from the client supplier while building, generator first, then in list order.
 */
public final class KmsMultiKeyrings {

  private KmsMultiKeyrings() {}

  /** The built multi keyring and the default client supplier it owns, if it made one. */
  public static final class Built {

    public final MultiKeyring keyring;
    private final DefaultClientSupplier ownedSupplier;

    private Built(MultiKeyring keyring, DefaultClientSupplier ownedSupplier) {
      this.keyring = keyring;
      this.ownedSupplier = ownedSupplier;
    }

    public void close() {
      if (ownedSupplier != null) {
        ownedSupplier.close();
      }
    }
  }

  /**
   * A generator keyring and one child keyring per key id, each given the client for its key's Region
   * ({@code ""} for a key id or alias without a Region).
   * {@code mrkAware} also rejects two identifiers of the same multi-Region key.
   */
  public static Built strict(
    String generator,
    List<String> kmsKeyIds,
    ClientSupplier clientSupplier,
    boolean mrkAware,
    BiFunction<KmsClient, String, Keyring> keyring,
    String missingKeyringsMessage
  ) {
    return withSupplier(
      clientSupplier,
      supplier -> {
        List<String> all = new ArrayList<>();
        if (generator != null) {
          all.add(generator);
        }
        all.addAll(kmsKeyIds);
        List<AwsKmsIdentifier> identifiers = new ArrayList<>();
        for (String keyId : all) {
          //= spec/framework/aws-kms/aws-kms-multi-keyrings.md#aws-kms-multi-keyring
          //= type=implication
          //# If any of the AWS KMS key identifiers is not a [valid AWS KMS key ARN]
          //# (aws-kms-key-arn.md#a-valid-aws-kms-arn), this function MUST fail.

          //= spec/framework/aws-kms/aws-kms-mrk-multi-keyrings.md#aws-kms-mrk-multi-keyring
          //= type=implication
          //# If any of the AWS KMS key identifiers is not a [valid AWS KMS key ARN]
          //# (aws-kms-key-arn.md#a-valid-aws-kms-arn), this function MUST fail All
          //# AWS KMS identifiers are passed to [Assert AWS KMS MRK are unique](aws-
          //# kms-mrk-are-unique.md#Implementation) and the function MUST return
          //# success otherwise this MUST fail.
          identifiers.add(AwsKmsIdentifier.parseIdentifierString(keyId));
        }
        if (mrkAware) {
          //= spec/framework/aws-kms/aws-kms-mrk-multi-keyrings.md#aws-kms-mrk-multi-keyring
          //= type=implication
          //# All
          //# AWS KMS identifiers are passed to [Assert AWS KMS MRK are unique](aws-
          //# kms-mrk-are-unique.md#Implementation) and the function MUST return
          //# success otherwise this MUST fail.
          AwsKmsIdentifier.requireUniqueMultiRegionKeys(identifiers);
        }
        List<Keyring> keyrings = new ArrayList<>();
        for (int i = 0; i < all.size(); i++) {
          //= spec/framework/aws-kms/aws-kms-multi-keyrings.md#aws-kms-multi-keyring
          //= type=implication
          //# NOTE: The AWS Encryption SDK SHOULD NOT attempt to evaluate its own
          //# default region.

          //= spec/framework/aws-kms/aws-kms-mrk-multi-keyrings.md#aws-kms-mrk-multi-keyring
          //= type=implication
          //# NOTE: The AWS Encryption SDK SHOULD NOT attempt to evaluate its own
          //# default region.
          keyrings.add(keyring.apply(supplier.getClient(identifiers.get(i).region()), all.get(i)));
        }
        if (keyrings.isEmpty()) {
          throw new ValidationException(missingKeyringsMessage);
        }
        Keyring generatorKeyring = generator == null ? null : keyrings.get(0);
        List<Keyring> children = generator == null ? keyrings : keyrings.subList(1, keyrings.size());
        //= spec/framework/aws-kms/aws-kms-multi-keyrings.md#aws-kms-multi-keyring
        //= type=implication
        //# Then a [Multi-Keyring](../multi-keyring.md#inputs) MUST be initialize
        //# by using this generator keyring as the [generator keyring](../multi-
        //# keyring.md#generator-keyring) and this set of child keyrings as the
        //# [child keyrings](../multi-keyring.md#child-keyrings).

        //= spec/framework/aws-kms/aws-kms-multi-keyrings.md#aws-kms-multi-keyring
        //= type=implication
        //# This Multi-
        //# Keyring MUST be this function's output.

        //= spec/framework/aws-kms/aws-kms-mrk-multi-keyrings.md#aws-kms-mrk-multi-keyring
        //= type=implication
        //# Then a [Multi-Keyring](../multi-keyring.md#inputs) MUST be initialize
        //# by using this generator keyring as the [generator keyring](../multi-
        //# keyring.md#generator-keyring) and this set of child keyrings as the
        //# [child keyrings](../multi-keyring.md#child-keyrings).
        //# This Multi-
        //# Keyring MUST be this functions output.
        return MultiKeyring.builder().generator(generatorKeyring).childKeyrings(children).build();
      }
    );
  }

  /** One discovery keyring per Region, as children of a multi keyring without a generator. */
  public static Built discovery(List<String> regions, ClientSupplier clientSupplier, BiFunction<KmsClient, String, Keyring> keyring) {
    return withSupplier(
      clientSupplier,
      supplier -> {
        //= spec/framework/aws-kms/aws-kms-multi-keyrings.md#aws-kms-discovery-multi-keyring
        //# If an empty set of Region is provided this function MUST fail.

        //= spec/framework/aws-kms/aws-kms-mrk-multi-keyrings.md#aws-kms-mrk-discovery-multi-keyring
        //# If an empty set of Region is provided this function MUST fail.
        if (regions.isEmpty()) {
          throw new ValidationException("No regions passed.");
        }
        //= spec/framework/aws-kms/aws-kms-multi-keyrings.md#aws-kms-discovery-multi-keyring
        //# If
        //# any element of the set of regions is null or an empty string this
        //# function MUST fail.

        //= spec/framework/aws-kms/aws-kms-mrk-multi-keyrings.md#aws-kms-mrk-discovery-multi-keyring
        //# If
        //# any element of the set of regions is null or an empty string this
        //# function MUST fail.
        if (regions.contains("")) {
          throw new ValidationException("Empty string is not a valid region.");
        }
        List<Keyring> children = new ArrayList<>();
        for (String region : regions) {
          //= spec/framework/aws-kms/aws-kms-multi-keyrings.md#aws-kms-discovery-multi-keyring
          //# A set of AWS KMS clients MUST be created by calling regional client
          //# supplier for each region in the input set of regions.

          //= spec/framework/aws-kms/aws-kms-mrk-multi-keyrings.md#aws-kms-mrk-discovery-multi-keyring
          //# A set of AWS KMS clients MUST be created by calling regional client
          //# supplier for each region in the input set of regions.
          children.add(keyring.apply(supplier.getClient(region), region));
        }
        //= spec/framework/aws-kms/aws-kms-multi-keyrings.md#aws-kms-discovery-multi-keyring
        //= type=implication
        //# Then a [Multi-Keyring](../multi-keyring.md#inputs) MUST be initialize
        //# by using this set of discovery keyrings as the [child keyrings]
        //# (../multi-keyring.md#child-keyrings).
        //# This Multi-Keyring MUST be
        //# this functions output.

        //= spec/framework/aws-kms/aws-kms-mrk-multi-keyrings.md#aws-kms-mrk-discovery-multi-keyring
        //= type=implication
        //# Then a [Multi-Keyring](../multi-keyring.md#inputs) MUST be initialize
        //# by using this set of discovery keyrings as the [child keyrings]
        //# (../multi-keyring.md#child-keyrings).
        //# This Multi-Keyring MUST be
        //# this functions output.
        return MultiKeyring.builder().childKeyrings(children).build();
      }
    );
  }

  /** An immutable copy; absent means empty. */
  public static List<String> copy(Collection<String> values) {
    return values == null ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(values));
  }

  // Without a supplier, a default one is made; it is closed again if building fails.
  private static Built withSupplier(ClientSupplier clientSupplier, Function<ClientSupplier, MultiKeyring> build) {
    if (clientSupplier != null) {
      return new Built(build.apply(clientSupplier), null);
    }
    //= spec/framework/aws-kms/aws-kms-multi-keyrings.md#aws-kms-multi-keyring
    //# If a regional client supplier is not passed, then a default MUST be
    //# created that takes a region string and generates a default AWS SDK
    //# client for the given region.

    //= spec/framework/aws-kms/aws-kms-multi-keyrings.md#aws-kms-discovery-multi-keyring
    //# If a regional client supplier is not passed, then a default MUST be created that takes a region string and generates a default AWS SDK client for the given region.

    //= spec/framework/aws-kms/aws-kms-mrk-multi-keyrings.md#aws-kms-mrk-multi-keyring
    //# If a regional client supplier is not passed, then a default MUST be created that takes a region string and generates a default AWS SDK client for the given region.

    //= spec/framework/aws-kms/aws-kms-mrk-multi-keyrings.md#aws-kms-mrk-discovery-multi-keyring
    //# If a regional client supplier is not passed, then a default MUST be created that takes a region string and generates a default AWS SDK client for the given region.
    DefaultClientSupplier owned = ClientSupplier.defaultSupplier();
    try {
      return new Built(build.apply(owned), owned);
    } catch (RuntimeException e) {
      owned.close();
      throw e;
    }
  }
}
