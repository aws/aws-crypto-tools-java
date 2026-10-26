// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

/**
 * Port of AwsArnParsing.dfy: KMS key identifiers and DynamoDB table ARNs.
 *
 * <p>Splitting keeps empty fields: {@code "a::b"} has three components.
 * Lengths are counted in UTF-16 units, as Dafny counts the characters of a Java string.
 */
public final class AwsArnParsing {

  private static final Pattern COLON = Pattern.compile(":");
  private static final Pattern SLASH = Pattern.compile("/");

  private AwsArnParsing() {}

  /**
   * A parsed AWS KMS key identifier: an ARN, or a raw resource ({@code key/<id>}, {@code alias/<name>}).
   * Equality is field by field, as for the Dafny datatype.
   */
  public static final class AwsKmsIdentifier {

    // IsAwsKmsIdentifierString and ValidateKmsKeyId accept at most this many characters.
    private static final int MAX_LENGTH = 2048;

    // Null for a raw resource identifier.
    private final String partition;
    private final String service;
    private final String region;
    private final String account;
    private final String resourceType;
    private final String resourceValue;

    private AwsKmsIdentifier(String partition, String service, String region, String account, String resourceType, String resourceValue) {
      this.partition = partition;
      this.service = service;
      this.region = region;
      this.account = account;
      this.resourceType = resourceType;
      this.resourceValue = resourceValue;
    }

    /** ParseAwsKmsIdentifier: an ARN if it starts with {@code arn:}, otherwise a raw resource. */
    public static AwsKmsIdentifier parse(String identifier) {
      return identifier.startsWith("arn:") ? parseArn(identifier) : parseRawResource(identifier);
    }

    /** ParseAwsKmsArn: six colon-separated parts, service {@code kms}, a {@code key} or {@code alias} resource. */
    public static AwsKmsIdentifier parseArn(String identifier) {
      String[] components = split(identifier, COLON);
      if (components.length != 6) {
        throw new ValidationException("Malformed arn: " + identifier);
      }
      String[] resource = parseResource(components[5]);
      boolean valid =
        //= spec/framework/aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-arn
        //= type=implication
        //# MUST start with string `arn`
        //= spec/framework/aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-arn
        //= type=implication
        //# The partition MUST be a non-empty
        //= spec/framework/aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-arn
        //= type=implication
        //# The service MUST be the string `kms`
        //= spec/framework/aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-arn
        //= type=implication
        //# The region MUST be a non-empty string
        //= spec/framework/aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-arn
        //= type=implication
        //# The account MUST be a non-empty string
        components[0].equals("arn") &&
        !components[1].isEmpty() &&
        components[2].equals("kms") &&
        !components[3].isEmpty() &&
        !components[4].isEmpty();
      if (!valid) {
        throw new ValidationException("Malformed Arn:" + identifier);
      }
      return new AwsKmsIdentifier(components[1], components[2], components[3], components[4], resource[0], resource[1]);
    }

    /** IsAwsKmsIdentifierString: ASCII, 1 to 2048 characters, then parsed. */
    public static AwsKmsIdentifier parseIdentifierString(String identifier) {
      if (!isAscii(identifier)) {
        throw new ValidationException("Not a valid ASCII string.");
      }
      if (identifier.isEmpty() || identifier.length() > MAX_LENGTH) {
        throw new ValidationException("Identifier exceeds maximum length.");
      }
      return parse(identifier);
    }

    /** ValidateKmsKeyId: parsed, then ASCII, then 1 to 2048 characters. */
    public static AwsKmsIdentifier validateKeyId(String keyId) {
      AwsKmsIdentifier parsed = parse(keyId);
      if (!isAscii(keyId)) {
        throw new ValidationException("Key identifier is not ASCII");
      }
      if (keyId.length() > MAX_LENGTH) {
        throw new ValidationException("Key identifier is too long");
      }
      return parsed;
    }

    /**
     * AwsKmsMrkAreUnique: no two multi-Region identifiers may share a key id.
     * The message lists every identifier whose key id is that of any multi-Region identifier, as Dafny does.
     */
    //= spec/framework/aws-kms/aws-kms-mrk-are-unique.md#implementation
    //= type=implication
    //# The caller MUST provide:
    public static void requireUniqueMultiRegionKeys(List<AwsKmsIdentifier> identifiers) {
      List<String> mrkKeyIds = new ArrayList<>();
      for (AwsKmsIdentifier identifier : identifiers) {
        if (identifier.isMultiRegion()) {
          mrkKeyIds.add(identifier.resourceValue);
        }
      }
      Set<String> distinct = new HashSet<>(mrkKeyIds);
      //= spec/framework/aws-kms/aws-kms-mrk-are-unique.md#implementation
      //= type=implication
      //# If the list does not contain any [multi-Region keys](aws-kms-key-
      //# arn.md#identifying-an-aws-kms-multi-region-key) this function MUST
      //# exit successfully.
      //= spec/framework/aws-kms/aws-kms-mrk-are-unique.md#implementation
      //= type=implication
      //# If there are zero duplicate resource ids between the multi-region
      //# keys, this function MUST exit successfully
      if (distinct.size() == mrkKeyIds.size()) {
        return;
      }
      List<String> duplicates = new ArrayList<>();
      for (AwsKmsIdentifier identifier : identifiers) {
        if (distinct.contains(identifier.resourceValue)) {
          duplicates.add(identifier.toString());
        }
      }
      //= spec/framework/aws-kms/aws-kms-mrk-are-unique.md#implementation
      //# If any duplicate multi-region resource ids exist, this function MUST
      //# yield an error that includes all identifiers with duplicate resource
      //# ids not only the first duplicate found.
      throw new ValidationException("Related multi-Region keys: " + String.join(",", duplicates) + "are not allowed.");
    }

    public boolean isArn() {
      return partition != null;
    }

    /** Empty for a raw resource identifier. */
    public String region() {
      return isArn() ? region : "";
    }

    public String partition() {
      return partition;
    }

    public String account() {
      return account;
    }

    public String resourceType() {
      return resourceType;
    }

    /** IsMultiRegionAwsKmsIdentifier: a {@code key} resource whose id starts with {@code mrk-}. */
    //= spec/framework/aws-kms/aws-kms-key-arn.md#identifying-an-an-aws-kms-multi-region-arn
    //= type=implication
    //# This function MUST take a single AWS KMS ARN
    //# If the input is an invalid AWS KMS ARN this function MUST error.
    //= spec/framework/aws-kms/aws-kms-key-arn.md#identifying-an-an-aws-kms-multi-region-arn
    //= type=implication
    //# If resource type is “alias”,
    //# this is an AWS KMS alias ARN and MUST return false.
    //= spec/framework/aws-kms/aws-kms-key-arn.md#identifying-an-an-aws-kms-multi-region-arn
    //= type=implication
    //# If resource type is “key” and resource ID starts with “mrk-“,
    //# this is a AWS KMS multi-Region key ARN and MUST return true.
    //= spec/framework/aws-kms/aws-kms-key-arn.md#identifying-an-an-aws-kms-multi-region-arn
    //= type=implication
    //# If resource type is “key” and resource ID does not start with “mrk-“,
    //# this is a (single-region) AWS KMS key ARN and MUST return false.
    //= spec/framework/aws-kms/aws-kms-key-arn.md#identifying-an-an-aws-kms-multi-region-identifier
    //= type=implication
    //# This function MUST take a single AWS KMS identifier
    //= spec/framework/aws-kms/aws-kms-key-arn.md#identifying-an-an-aws-kms-multi-region-identifier
    //= type=implication
    //# If the input starts with "arn:",
    //# this MUST return the output of [identifying an an AWS KMS multi-Region ARN](aws-kms-key-arn.md#identifying-an-an-aws-kms-multi-region-arn)
    //# called with this input.
    //= spec/framework/aws-kms/aws-kms-key-arn.md#identifying-an-an-aws-kms-multi-region-identifier
    //= type=implication
    //# If the input starts with “alias/“,
    //# this an AWS KMS alias and not a multi-Region key id and MUST return false.
    //= spec/framework/aws-kms/aws-kms-key-arn.md#identifying-an-an-aws-kms-multi-region-identifier
    //= type=implication
    //# If the input starts with “mrk-“,
    //# this is a multi-Region key id and MUST return true.
    //= spec/framework/aws-kms/aws-kms-key-arn.md#identifying-an-an-aws-kms-multi-region-identifier
    //= type=implication
    //# If
    //# the input does not start with any of the above, this is not a multi-
    //# Region key id and MUST return false.
    public boolean isMultiRegion() {
      return resourceType.equals("key") && resourceValue.startsWith("mrk-");
    }

    /**
     * AwsKmsMrkMatchForDecrypt for two ARNs: identical, or the same multi-Region key in any two regions.
     * Equal resources make {@code message} multi-Region whenever this ARN is, so only this one is checked.
     */
    //= spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation
    //= type=implication
    //# The caller MUST provide:
    //# *  2 AWS KMS key identifiers
    public boolean mrkMatches(AwsKmsIdentifier message) {
      //= spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation
      //= type=implication
      //# If both identifiers are identical, this function MUST return `true`.
      if (equals(message)) {
        return true;
      }
      return (
        //= spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation
        //= type=implication
        //# Otherwise if either input is not [identified as a multi-Region key]
        //# (aws-kms-key-arn.md#identifying-an-aws-kms-multi-region-key), then
        //# this function MUST return `false`.
        //= spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation
        //= type=implication
        //# Otherwise if both inputs are
        //# [identified as a multi-Region keys](aws-kms-key-arn.md#identifying-an-
        //# aws-kms-multi-region-key), this function MUST return the result of
        //# comparing the `partition`, `service`, `accountId`, `resourceType`,
        //# and `resource` parts of both ARN inputs.
        isMultiRegion() &&
        partition.equals(message.partition) &&
        service.equals(message.service) &&
        account.equals(message.account) &&
        resourceType.equals(message.resourceType) &&
        resourceValue.equals(message.resourceValue)
      );
    }

    /** ToArnString(Some(region)): this ARN with another region. */
    public String toArnString(String otherRegion) {
      return String.join(":", "arn", partition, service, otherRegion, account, resourceType + "/" + resourceValue);
    }

    /** The ARN, or {@code type/value} for a raw resource; the resource separator is always {@code /}. */
    @Override
    public String toString() {
      return isArn() ? toArnString(region) : resourceType + "/" + resourceValue;
    }

    @Override
    public boolean equals(Object other) {
      if (!(other instanceof AwsKmsIdentifier)) {
        return false;
      }
      AwsKmsIdentifier that = (AwsKmsIdentifier) other;
      return (
        Objects.equals(partition, that.partition) &&
        Objects.equals(service, that.service) &&
        Objects.equals(region, that.region) &&
        Objects.equals(account, that.account) &&
        resourceType.equals(that.resourceType) &&
        resourceValue.equals(that.resourceValue)
      );
    }

    @Override
    public int hashCode() {
      return Objects.hash(partition, service, region, account, resourceType, resourceValue);
    }

    // ParseAwsKmsRawResources: a bare key id means key/<id>; "key/..." must be written as an ARN or a bare id.
    private static AwsKmsIdentifier parseRawResource(String identifier) {
      String[] info = split(identifier, SLASH);
      if (info[0].equals("key")) {
        throw new ValidationException("Malformed raw key id: " + identifier);
      }
      String[] resource = parseResource(info.length == 1 ? "key/" + identifier : identifier);
      return new AwsKmsIdentifier(null, null, null, null, resource[0], resource[1]);
    }

    // ParseAwsKmsResources: {type, value}, split at the first slash; later slashes stay in the value.
    private static String[] parseResource(String identifier) {
      String[] info = split(identifier, SLASH);
      //= spec/framework/aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-arn
      //= type=implication
      //# The resource section MUST be non-empty and MUST be split by a
      //# single `/` any additional `/` are included in the resource id
      if (info.length < 2) {
        throw new ValidationException("Malformed resource: " + identifier);
      }
      String type = info[0];
      String value = String.join("/", Arrays.asList(info).subList(1, info.length));
      //= spec/framework/aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-arn
      //= type=implication
      //# The resource type MUST be either `alias` or `key`
      //= spec/framework/aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-arn
      //= type=implication
      //# The resource id MUST be a non-empty string
      if (value.isEmpty() || !(type.equals("key") || type.equals("alias"))) {
        throw new ValidationException("Malformed resource: " + identifier);
      }
      return new String[] { type, value };
    }
  }

  /**
   * ParseAmazonDynamodbTableName: the table name of a DynamoDB table ARN, or null if {@code arn} is not one.
   * The name is not checked against the TableName length limits; the key store compares it with a valid name.
   */
  public static String dynamoDbTableName(String arn) {
    String[] components = split(arn, COLON);
    if (components.length != 6) {
      return null;
    }
    String resource = components[5];
    int slash = resource.indexOf('/');
    if (slash < 0) {
      return null;
    }
    String resourceType = resource.substring(0, slash);
    String tableName = resource.substring(slash + 1);
    boolean valid =
      resourceType.equals("table") &&
      components[0].equals("arn") &&
      !components[1].isEmpty() &&
      components[2].equals("dynamodb") &&
      !components[3].isEmpty() &&
      !components[4].isEmpty();
    return valid ? tableName : null;
  }

  // Dafny's Split: every segment, including empty ones at either end.
  private static String[] split(String value, Pattern delimiter) {
    return delimiter.split(value, -1);
  }

  private static boolean isAscii(String value) {
    for (int i = 0; i < value.length(); i++) {
      if (value.charAt(i) > 127) {
        return false;
      }
    }
    return true;
  }
}
