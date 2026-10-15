// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal.keystore;

import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.AwsArnParsing.AwsKmsIdentifier;

/**
 * The key store's checks on KMS key ARNs, per KmsArn.dfy and KMSKeystoreOperations.dfy, over {@link AwsKmsIdentifier}.
 * They report an ARN that does not parse as null or false instead of an exception.
 */
public final class Arns {

  /** KMS KeyIdType: 1 to 2048 characters. */
  private static final int MAX_KEY_ID_LENGTH = 2048;

  private Arns() {}

  /** The parsed ARN, or null if {@code identifier} is not a KMS ARN. */
  static AwsKmsIdentifier parseKmsArn(String identifier) {
    try {
      return AwsKmsIdentifier.parseArn(identifier);
    } catch (ValidationException e) {
      return null;
    }
  }

  /**
   * Checks a configured KMS key ARN (KmsArn.IsValidKeyArn).
   *
   * @return null if valid, otherwise the failure message
   */
  public static String keyArnFailure(String identifier) {
    if (!isValidKeyIdLength(identifier)) {
      return KeyStoreMessages.KMS_CONFIG_KMS_ARN_INVALID;
    }
    AwsKmsIdentifier arn;
    try {
      arn = AwsKmsIdentifier.parseArn(identifier);
    } catch (ValidationException e) {
      return KeyStoreMessages.KMS_CONFIG_KMS_ARN_INVALID + ". " + e.getMessage();
    }
    //= spec/framework/branch-key-store.md#aws-kms-configuration
    //# This ARN MUST NOT be an Alias.
    if (!arn.resourceType().equals("key")) {
      return KeyStoreMessages.ALIAS_NOT_ALLOWED;
    }
    return null;
  }

  /** KmsArn.ValidKmsArn?: a KeyIdType-length string that parses as a KMS ARN of resource type {@code key}. */
  static boolean isValidKeyArn(String identifier) {
    return keyArnFailure(identifier) == null;
  }

  /** KMS KeyIdType length: 1 to 2048. */
  static boolean isValidKeyIdLength(String identifier) {
    return identifier.length() >= 1 && identifier.length() <= MAX_KEY_ID_LENGTH;
  }

  /**
   * MrkMatch: whether a stored ARN names the configured key for decryption, as AwsKmsMrkMatchForDecrypt decides.
   * False if either does not parse.
   */
  static boolean mrkMatch(String configured, String stored) {
    AwsKmsIdentifier a = parseKmsArn(configured);
    AwsKmsIdentifier b = parseKmsArn(stored);
    return a != null && b != null && a.mrkMatches(b);
  }

  /** replaceRegion: a multi-Region key ARN with its region replaced, unless the result is too long; any other value unchanged. */
  static String replaceRegion(String arn, String region) {
    AwsKmsIdentifier parsed = parseKmsArn(arn);
    if (parsed == null || !parsed.isMultiRegion()) {
      return arn;
    }
    String replaced = parsed.toArnString(region);
    return isValidKeyIdLength(replaced) ? replaced : arn;
  }
}
