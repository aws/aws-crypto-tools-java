// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keystore;

import java.util.Objects;
import java.util.Optional;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.keystore.Arns;

/** Which KMS key protects the branch keys. Create one with the static methods. Immutable. */
public abstract class KmsConfiguration {

  /** The kinds, for {@code switch}. More kinds may be added; include a {@code default} branch. */
  public enum Kind {
    KMS_KEY_ARN,
    KMS_MR_KEY_ARN,
    DISCOVERY,
    MR_DISCOVERY,
  }

  // KMS RegionType: 1 to 32 characters.
  private static final int MAX_REGION_LENGTH = 32;

  private KmsConfiguration() {}

  /**
   * Exactly this key; not an alias.
   *
   * @throws ValidationException if {@code kmsKeyArn} is not a KMS key ARN
   */
  //= spec/framework/branch-key-store.md#aws-kms-configuration
  //= type=implication
  //# `KMS Key ARN` and `KMS MRKey ARN` MUST take an additional argument
  //# that is a KMS ARN.
  public static KmsConfiguration kmsKeyArn(String kmsKeyArn) {
    return new Configured(Kind.KMS_KEY_ARN, checkKeyArn(kmsKeyArn), null);
  }

  /**
   * This multi-Region key or any replica of it.
   * A key that is not multi-Region behaves as with {@link #kmsKeyArn}.
   *
   * @throws ValidationException if {@code kmsMrKeyArn} is not a KMS key ARN
   */
  public static KmsConfiguration kmsMrKeyArn(String kmsMrKeyArn) {
    return new Configured(Kind.KMS_MR_KEY_ARN, checkKeyArn(kmsMrKeyArn), null);
  }

  /** Whatever key each branch key names; read only. */
  public static KmsConfiguration discovery() {
    return new Configured(Kind.DISCOVERY, null, null);
  }

  /**
   * Whatever multi-Region key each branch key names, used through {@code region}; read only.
   *
   * @throws ValidationException if {@code region} is empty or longer than 32 characters
   */
  //= spec/framework/branch-key-store.md#aws-kms-configuration
  //= type=implication
  //# `MRDiscovery` MUST take an additional argument, which is a region.
  public static KmsConfiguration mrDiscovery(String region) {
    Objects.requireNonNull(region, "region");
    if (region.isEmpty()) {
      throw new ValidationException("The size of `region` must be greater than or equal to 1");
    }
    if (region.length() > MAX_REGION_LENGTH) {
      throw new ValidationException("The size of `region` must be less than or equal to 32");
    }
    return new Configured(Kind.MR_DISCOVERY, null, region);
  }

  public abstract Kind kind();

  /** The KMS key ARN of a {@code KMS_KEY_ARN} or {@code KMS_MR_KEY_ARN} configuration; empty for the discovery kinds. */
  public abstract Optional<String> arn();

  /** The Region of an {@code MR_DISCOVERY} configuration; empty for the other kinds. */
  public abstract Optional<String> region();

  private static String checkKeyArn(String arn) {
    Objects.requireNonNull(arn, "KMS key ARN");
    //= spec/framework/branch-key-store.md#aws-kms-configuration
    //= type=implication
    //# This ARN MUST be a valid
    //# [AWS KMS Key ARN](./aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-arn).
    String failure = Arns.keyArnFailure(arn);
    if (failure != null) {
      throw new ValidationException(failure);
    }
    return arn;
  }

  private static final class Configured extends KmsConfiguration {

    private final Kind kind;
    private final String arn;
    private final String region;

    Configured(Kind kind, String arn, String region) {
      this.kind = kind;
      this.arn = arn;
      this.region = region;
    }

    @Override
    public Kind kind() {
      return kind;
    }

    @Override
    public Optional<String> arn() {
      return Optional.ofNullable(arn);
    }

    @Override
    public Optional<String> region() {
      return Optional.ofNullable(region);
    }

    @Override
    public boolean equals(Object other) {
      if (!(other instanceof Configured)) {
        return false;
      }
      Configured that = (Configured) other;
      return kind == that.kind && Objects.equals(arn, that.arn) && Objects.equals(region, that.region);
    }

    @Override
    public int hashCode() {
      return Objects.hash(kind, arn, region);
    }

    @Override
    public String toString() {
      String value = arn != null ? arn : region;
      return "KmsConfiguration[" + kind + (value == null ? "" : ", " + value) + "]";
    }
  }
}
