// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.keystore;

/** Failure messages of the key store, as in KeyStoreErrorMessages.dfy and the operations that inline theirs. */
final class KeyStoreMessages {

  static final String KMS_CONFIG_KMS_ARN_INVALID = "KMSConfiguration's KMS Key ARN is invalid.";
  static final String CUSTOM_BRANCH_KEY_ID_NEED_EC = "Custom branch key identifier requires custom encryption context.";
  static final String GET_KEY_ARN_DISAGREEMENT =
    "Branch key's KMS Key ARN read from Dynamodb does not match Key Store's configured KMS Key ARN.";
  static final String VERSION_KEY_KMS_KEY_ARN_DISAGREEMENT = GET_KEY_ARN_DISAGREEMENT;
  static final String GET_KEY_VERSION_ARN_DISAGREEMENT = "AWS KMS Key ARN does not match configured value";
  static final String DISCOVERY_CREATE_KEY_NOT_SUPPORTED =
    "Key Store's kmsConfiguration MUST BE kmsKeyArn or kmsMRKeyArn to Create Branch Keys.";
  static final String DISCOVERY_VERSION_KEY_NOT_SUPPORTED =
    "Key Store's kmsConfiguration MUST BE kmsKeyArn or kmsMRKeyArn to Version Branch Keys.";
  static final String UTF8_ENCODING_ENCRYPTION_CONTEXT_ERROR = "Unable to UTF8 Encode element of Encryption Context.";
  static final String ALIAS_NOT_ALLOWED =
    "Key Store encountered a KMS Alias ARN instead of a KMS Key ARN, which is not allowed.";
  static final String NO_CORRESPONDING_BRANCH_KEY = "No item found for corresponding branch key identifier.";
  static final String BRANCH_KEY_ID_NEEDED = "Empty string not supported for branch key identifier.";
  static final String CUSTOM_BRANCH_KEY_ID_EMPTY = "Custom branch key id can not be an empty string.";
  static final String RETRIEVED_KEYSTORE_ITEM_INVALID_KMS_ARN =
    "The `kms-arn` field for the requested branch key identifier is corrupted.";
  static final String INVALID_GRANT_TOKENS = "Grant Tokens passed to Key Store configuration are invalid.";
  static final String INVALID_TABLE_NAME = "Invalid Amazon DynamoDB Table Name";
  static final String TABLE_NOT_KEY_STORE = "Configured table name does not conform to expected Key Store construction.";
  static final String TABLE_ARN_MISMATCH = "Configured DDB Table Name does not match parsed Table Name from DDB Table Arn.";
  static final String INVALID_ACTIVE_ITEM = "Item found is not a valid active branch key.";
  static final String INVALID_VERSION_ITEM = "Item found is not a valid branch key version.";
  static final String INVALID_BEACON_ITEM = "Item found is not a valid beacon key.";
  static final String GENERATE_INVALID_KEY_ID = "Invalid response from KMS GenerateDataKey:: Invalid Key Id";
  static final String GENERATE_INVALID_CIPHERTEXT = "Invalid response from AWS KMS GenerateDataKey: Invalid ciphertext";
  static final String RE_ENCRYPT_INVALID_KEY_ID = "Invalid response from KMS ReEncrypt:: Invalid Key Id";
  static final String RE_ENCRYPT_INVALID_CIPHERTEXT = "Invalid response from AWS KMS ReEncrypt: Invalid ciphertext.";
  static final String DECRYPT_INVALID_KEY = "Invalid response from AWS KMS Decrypt: Key is not 32 bytes.";
  // The Dafny runtime's UTF-8 encoder message, for a branch key version that is not well-formed UTF-16.
  static final String VERSION_NOT_UTF8 = "Could not encode input to Dafny Bytes.";
  static final String CONTEXT_NOT_UTF8 = "Unable to encode string";

  private KeyStoreMessages() {}
}
