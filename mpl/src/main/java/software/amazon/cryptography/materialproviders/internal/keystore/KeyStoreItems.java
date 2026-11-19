// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.keystore;

import java.util.HashMap;
import java.util.Map;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

/**
 * The key store's DynamoDB items and the KMS encryption contexts they map to, per Structure.dfy.
 *
 * <p>An item holds every field of its encryption context as an attribute, except {@code tablename},
 * plus the wrapped key in {@code enc}. {@code hierarchy-version} is a number attribute, the rest are strings.
 * Reading an item back adds {@code tablename} = the logical key store name,
 * so every string attribute of a stored item, known or not, is part of the context KMS checks.
 */
public final class KeyStoreItems {

  static final String BRANCH_KEY_IDENTIFIER_FIELD = "branch-key-id";
  static final String TYPE_FIELD = "type";
  static final String KEY_CREATE_TIME = "create-time";
  static final String HIERARCHY_VERSION = "hierarchy-version";
  static final String TABLE_FIELD = "tablename";
  static final String KMS_FIELD = "kms-arn";
  static final String BRANCH_KEY_FIELD = "enc";
  static final String BRANCH_KEY_ACTIVE_VERSION_FIELD = "version";

  static final String BRANCH_KEY_TYPE_PREFIX = "branch:version:";
  static final String BRANCH_KEY_ACTIVE_TYPE = "branch:ACTIVE";
  static final String BEACON_KEY_TYPE_VALUE = "beacon:ACTIVE";
  /** Prefix of the attribute names that hold the caller's encryption context. */
  public static final String ENCRYPTION_CONTEXT_PREFIX = "aws-crypto-ec:";

  // DynamoDB TableName: 3 to 255 characters. AttributeName: up to 65535.
  private static final int MIN_TABLE_NAME_LENGTH = 3;
  private static final int MAX_TABLE_NAME_LENGTH = 255;
  private static final int MAX_ATTRIBUTE_NAME_LENGTH = 65535;
  // KMS CiphertextType: 1 to 6144 bytes.
  private static final int MAX_CIPHERTEXT_LENGTH = 6144;

  private KeyStoreItems() {}

  static boolean isValidTableName(String tableName) {
    return tableName.length() >= MIN_TABLE_NAME_LENGTH && tableName.length() <= MAX_TABLE_NAME_LENGTH;
  }

  /** Whether {@code key} of the caller's encryption context makes a valid attribute name once prefixed. */
  static boolean isValidCustomKey(String key) {
    return ENCRYPTION_CONTEXT_PREFIX.length() + key.length() <= MAX_ATTRIBUTE_NAME_LENGTH;
  }

  static boolean isValidCiphertext(byte[] ciphertext) {
    return ciphertext.length >= 1 && ciphertext.length <= MAX_CIPHERTEXT_LENGTH;
  }

  /** The DECRYPT_ONLY context of a new branch key version. */
  static Map<String, String> decryptOnlyContext(
    String branchKeyId,
    String branchKeyVersion,
    String timestamp,
    String logicalKeyStoreName,
    String kmsKeyArn,
    Map<String, String> customEncryptionContext
  ) {
    Map<String, String> context = new HashMap<>();
    //= spec/framework/branch-key-store.md#encryption-context
    //= type=implication
    //# - MUST have a `branch-key-id` attribute

    //= spec/framework/branch-key-store.md#encryption-context
    //= type=implication
    //# - MUST have a `type` attribute

    //= spec/framework/branch-key-store.md#encryption-context
    //= type=implication
    //# - MUST have a `create-time` attribute

    //= spec/framework/branch-key-store.md#encryption-context
    //= type=implication
    //# - MUST have a `hierarchy-version`

    //= spec/framework/branch-key-store.md#encryption-context
    //= type=implication
    //# - MUST have a `tablename` attribute to store the logicalKeyStoreName

    //= spec/framework/branch-key-store.md#encryption-context
    //= type=implication
    //# - MUST have a `kms-arn` attribute

    //= spec/framework/branch-key-store.md#encryption-context
    //= type=implication
    //# - MUST NOT have a `enc` attribute

    //= spec/framework/branch-key-store.md#decrypt-only-encryption-context
    //= type=implication
    //# The DECRYPT_ONLY encryption context MUST NOT have a `version` attribute.

    //= spec/framework/branch-key-store.md#decrypt-only-encryption-context
    //= type=implication
    //# The `type` attribute MUST stores the branch key version formatted like `"branch:version:"` + `version`.
    context.put(BRANCH_KEY_IDENTIFIER_FIELD, branchKeyId);
    context.put(TYPE_FIELD, BRANCH_KEY_TYPE_PREFIX + branchKeyVersion);
    context.put(KEY_CREATE_TIME, timestamp);
    //= spec/framework/branch-key-store.md#logical-keystore-name
    //= type=implication
    //# The logical keystore name MUST be bound to every created key.
    context.put(TABLE_FIELD, logicalKeyStoreName);
    context.put(KMS_FIELD, kmsKeyArn);
    context.put(HIERARCHY_VERSION, "1");
    //= spec/framework/branch-key-store.md#custom-encryption-context
    //= type=implication
    //# If custom [encryption context](./structures.md#encryption-context-3)
    //# is associated with the branch key these values MUST be added to the AWS KMS encryption context.

    //= spec/framework/branch-key-store.md#custom-encryption-context
    //= type=implication
    //# To avoid name collisions each added attribute from the custom [encryption context](./structures.md#encryption-context-3)
    //# MUST be prefixed with `aws-crypto-ec:`.
    for (Map.Entry<String, String> entry : customEncryptionContext.entrySet()) {
      context.put(ENCRYPTION_CONTEXT_PREFIX + entry.getKey(), entry.getValue());
    }
    return context;
  }

  /** The ACTIVE context of the version whose DECRYPT_ONLY context is given. */
  static Map<String, String> activeContext(Map<String, String> decryptOnlyContext) {
    Map<String, String> context = new HashMap<>(decryptOnlyContext);
    //= spec/framework/branch-key-store.md#active-encryption-context
    //= type=implication
    //# The ACTIVE encryption context MUST have a `version` attribute.

    //= spec/framework/branch-key-store.md#active-encryption-context
    //= type=implication
    //# The `version` attribute MUST store the branch key version formatted like `"branch:version:"` + `version`.
    context.put(BRANCH_KEY_ACTIVE_VERSION_FIELD, decryptOnlyContext.get(TYPE_FIELD));
    //= spec/framework/branch-key-store.md#active-encryption-context
    //= type=implication
    //# The ACTIVE encryption context value of the `type` attribute MUST equal to `"branch:ACTIVE"`.
    context.put(TYPE_FIELD, BRANCH_KEY_ACTIVE_TYPE);
    return context;
  }

  /** The beacon key context of the branch key whose first DECRYPT_ONLY context is given. */
  //= spec/framework/branch-key-store.md#beacon-key-encryption-context
  //= type=implication
  //# The Beacon key encryption context MUST NOT have a `version` attribute.
  static Map<String, String> beaconContext(Map<String, String> decryptOnlyContext) {
    Map<String, String> context = new HashMap<>(decryptOnlyContext);
    //= spec/framework/branch-key-store.md#beacon-key-encryption-context
    //= type=implication
    //# The Beacon key encryption context value of the `type` attribute MUST equal to `"beacon:ACTIVE"`.
    context.put(TYPE_FIELD, BEACON_KEY_TYPE_VALUE);
    return context;
  }

  /** A new DECRYPT_ONLY context made from the current ACTIVE one; it keeps every other attribute. */
  //= spec/framework/branch-key-store.md#custom-encryption-context
  //= type=implication
  //# Across all versions of a Branch Key, the custom encryption context MUST be equal.

  //= spec/framework/branch-key-store.md#versionkey
  //= type=implication
  //# The `kms-arn` stored in the DDB table MUST NOT change as a result of this operation,
  //# even if the KeyStore is configured with a `KMS MRKey ARN` that does not exactly match the stored ARN.
  static Map<String, String> newVersionContext(Map<String, String> activeContext, String branchKeyVersion, String timestamp) {
    Map<String, String> context = new HashMap<>(activeContext);
    context.put(TYPE_FIELD, BRANCH_KEY_TYPE_PREFIX + branchKeyVersion);
    context.put(KEY_CREATE_TIME, timestamp);
    context.remove(BRANCH_KEY_ACTIVE_VERSION_FIELD);
    return context;
  }

  /** The item that stores {@code wrappedKey} under {@code context} (ToAttributeMap). */
  //= spec/framework/branch-key-store.md#writing-branch-key-and-beacon-key-to-keystore
  //= type=implication
  //# - Every key-value pair of the custom [encryption context](./structures.md#encryption-context-3) that is associated with the branch key
  //# MUST be added with an Attribute Name of `aws-crypto-ec:` + the Key and Attribute Value (S) of the value.
  //= spec/framework/branch-key-store.md#versionkey
  //= type=implication
  //# - Every key-value pair of the custom [encryption context](./structures.md#encryption-context-3) that is associated with the branch key
  //# MUST be added with an Attribute Name of `aws-crypto-ec:` + the Key and Attribute Value (S) of the value.
  static Map<String, AttributeValue> toItem(Map<String, String> context, byte[] wrappedKey) {
    Map<String, AttributeValue> item = new HashMap<>();
    for (Map.Entry<String, String> entry : context.entrySet()) {
      String name = entry.getKey();
      if (name.equals(TABLE_FIELD)) {
        continue;
      }
      item.put(
        name,
        name.equals(HIERARCHY_VERSION)
          ? AttributeValue.builder().n(entry.getValue()).build()
          : AttributeValue.builder().s(entry.getValue()).build()
      );
    }
    item.put(BRANCH_KEY_FIELD, AttributeValue.builder().b(SdkBytes.fromByteArray(wrappedKey)).build());
    return item;
  }

  /** The KMS encryption context of a valid item (ToBranchKeyContext). */
  //= spec/framework/branch-key-store.md#encryption-context
  //= type=implication
  //# Any additionally attributes on the DynamoDB item
  //# MUST be added to the encryption context.

  //= spec/framework/branch-key-store.md#authenticating-a-keystore-item
  //= type=implication
  //# Every key in the constructed [encryption context](#encryption-context)
  //# except `tableName`
  //# MUST exist as a string attribute in the AWS DDB response item.

  //= spec/framework/branch-key-store.md#authenticating-a-keystore-item
  //= type=implication
  //# Every value in the constructed [encryption context](#encryption-context)
  //# except the logical table name
  //# MUST equal the value with the same key in the AWS DDB response item.

  //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
  //= type=implication
  //# Every key in the constructed [encryption context](#encryption-context)
  //# except `tableName`
  //# MUST exist as a string attribute in the AWS DDB response item.

  //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
  //= type=implication
  //# Every value in the constructed [encryption context](#encryption-context)
  //# except the logical table name
  //# MUST equal the value with the same key in the AWS DDB response item.
  static Map<String, String> toContext(Map<String, AttributeValue> item, String logicalKeyStoreName) {
    Map<String, String> context = new HashMap<>();
    for (Map.Entry<String, AttributeValue> entry : item.entrySet()) {
      String name = entry.getKey();
      //= spec/framework/branch-key-store.md#authenticating-a-keystore-item
      //# The key `enc` MUST NOT exist in the constructed [encryption context](#encryption-context).

      //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
      //= type=implication
      //# The key `enc` MUST NOT exist in the constructed [encryption context](#encryption-context).
      if (name.equals(BRANCH_KEY_FIELD)) {
        continue;
      }
      context.put(name, name.equals(HIERARCHY_VERSION) ? entry.getValue().n() : entry.getValue().s());
    }
    context.put(TABLE_FIELD, logicalKeyStoreName);
    return context;
  }

  /** The wrapped key of a valid item. */
  static byte[] wrappedKey(Map<String, AttributeValue> item) {
    return item.get(BRANCH_KEY_FIELD).b().asByteArray();
  }

  /**
   * Whether {@code item} is a valid key store item stored under {@code branchKeyId} and {@code type}
   * (ActiveBranchKeyItem?, VersionBranchKeyItem?, or BeaconKeyItem?, plus the key the read asked for).
   */
  static boolean isValid(Map<String, AttributeValue> item, String branchKeyId, String type) {
    return (
      isBranchKeyItem(item) &&
      item.get(BRANCH_KEY_IDENTIFIER_FIELD).s().equals(branchKeyId) &&
      item.get(TYPE_FIELD).s().equals(type)
    );
  }

  // BranchKeyItem?: the attributes every key store item has, with their types, and a consistent type and version.
  //= spec/framework/branch-key-store.md#record-format
  //= type=implication
  //# A branch key record MUST include the following key-value pairs:

  //= spec/framework/branch-key-store.md#record-format
  //= type=implication
  //# A branch key record MAY include [custom encryption context](#custom-encryption-context) key-value pairs.
  private static boolean isBranchKeyItem(Map<String, AttributeValue> item) {
    if (
      !hasType(item, BRANCH_KEY_IDENTIFIER_FIELD, AttributeValue.Type.S) ||
      !hasType(item, TYPE_FIELD, AttributeValue.Type.S) ||
      !hasType(item, KEY_CREATE_TIME, AttributeValue.Type.S) ||
      !hasType(item, HIERARCHY_VERSION, AttributeValue.Type.N) ||
      item.containsKey(TABLE_FIELD) ||
      !hasType(item, KMS_FIELD, AttributeValue.Type.S) ||
      !Arns.isValidKeyIdLength(item.get(KMS_FIELD).s()) ||
      !hasType(item, BRANCH_KEY_FIELD, AttributeValue.Type.B)
    ) {
      return false;
    }
    // An empty type cannot equal the type a read asks for, so only the id needs this check.
    //= spec/framework/branch-key-store.md#encryption-context
    //= type=implication
    //# - The `branch-key-id` field MUST not be an empty string
    if (item.get(BRANCH_KEY_IDENTIFIER_FIELD).s().isEmpty()) {
      return false;
    }
    for (Map.Entry<String, AttributeValue> entry : item.entrySet()) {
      String name = entry.getKey();
      if (!name.equals(BRANCH_KEY_FIELD) && !name.equals(HIERARCHY_VERSION) && entry.getValue().type() != AttributeValue.Type.S) {
        return false;
      }
    }
    //= spec/framework/branch-key-store.md#encryption-context
    //= type=implication
    //# - The `type` field MUST not be an empty string

    //= spec/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context
    //= type=implication
    //# The `type` attribute MUST either be equal to `"branch:ACTIVE"` or start with `"branch:version:"`.
    String type = item.get(TYPE_FIELD).s();
    boolean hasVersion = item.containsKey(BRANCH_KEY_ACTIVE_VERSION_FIELD);
    if (hasVersion != type.equals(BRANCH_KEY_ACTIVE_TYPE)) {
      return false;
    }
    if (hasVersion && !isVersionType(item.get(BRANCH_KEY_ACTIVE_VERSION_FIELD).s())) {
      return false;
    }
    if (!hasVersion != (type.equals(BEACON_KEY_TYPE_VALUE) || isVersionType(type))) {
      return false;
    }
    return isValidCiphertext(item.get(BRANCH_KEY_FIELD).b().asByteArray());
  }

  private static boolean hasType(Map<String, AttributeValue> item, String name, AttributeValue.Type type) {
    AttributeValue value = item.get(name);
    return value != null && value.type() == type;
  }

  // Dafny's strict prefix: "branch:version:" followed by at least one character.
  private static boolean isVersionType(String type) {
    return type.startsWith(BRANCH_KEY_TYPE_PREFIX) && type.length() > BRANCH_KEY_TYPE_PREFIX.length();
  }

  /** The version named by a valid branch key context: from {@code version} if ACTIVE, else from {@code type}. */
  //= spec/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context
  //= type=implication
  //# If the `type` attribute is equal to `"branch:ACTIVE"`
  //# then the authenticated encryption context MUST have a `version` attribute
  //# and the version string is this value.

  //= spec/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context
  //= type=implication
  //# If the `type` attribute start with `"branch:version:"` then the version string MUST be equal to this value.

  //= spec/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context
  //= type=implication
  //# - [Branch Key Version](./structures.md#branch-key-version)
  //# The version string MUST start with `branch:version:`.
  static String versionOf(Map<String, String> context) {
    String versionInformation = context.containsKey(BRANCH_KEY_ACTIVE_VERSION_FIELD)
      ? context.get(BRANCH_KEY_ACTIVE_VERSION_FIELD)
      : context.get(TYPE_FIELD);
    return versionInformation.substring(BRANCH_KEY_TYPE_PREFIX.length());
  }

  /** The caller's encryption context stored in a branch key context: the prefixed entries, prefix removed. */
  //= spec/framework/branch-key-store.md#custom-encryption-context-from-authenticated-encryption-context
  //= type=implication
  //# For every key in the [encryption context](./structures.md#encryption-context-3)
  //# the string `aws-crypto-ec:` + the UTF8 decode of this key
  //# MUST exist as a key in the authenticated encryption context.

  //= spec/framework/branch-key-store.md#custom-encryption-context-from-authenticated-encryption-context
  //= type=implication
  //# Also, the value in the [encryption context](./structures.md#encryption-context-3) for this key
  //# MUST equal the value in the authenticated encryption context
  //# for the constructed key.
  static Map<String, String> customContext(Map<String, String> context) {
    Map<String, String> custom = new HashMap<>();
    for (Map.Entry<String, String> entry : context.entrySet()) {
      if (entry.getKey().startsWith(ENCRYPTION_CONTEXT_PREFIX)) {
        custom.put(entry.getKey().substring(ENCRYPTION_CONTEXT_PREFIX.length()), entry.getValue());
      }
    }
    return custom;
  }
}
