// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

/** Checks and messages shared by the keyrings, per AwsKmsUtils.dfy and ErrorMessages.dfy. */
public final class KeyringNames {

  /** How ErrorMessages.IncorrectDataKeys starts. */
  public static final String INCORRECT_DATA_KEYS = "Unable to decrypt data key: No Encrypted Data Keys found to match. \n Expected: \n";

  private static final int UINT16_LIMIT = 65536;
  private static final String HIERARCHY_PROVIDER_ID = "aws-kms-hierarchy";
  // Where a hierarchical keyring's wrapped material holds the branch key version: after a 16-byte salt and a 12-byte IV.
  private static final int BRANCH_KEY_VERSION_INDEX = 28;
  private static final int BRANCH_KEY_VERSION_LENGTH = 16;
  /** The message of the Dafny runtime's UTF-8 encoder and decoder; ParseKeyNamespaceAndName appends it. */
  public static final String UTF8_FAILURE = "Could not encode input to Dafny Bytes.";

  private KeyringNames() {}

  public static void requireSet(Object value, String field) {
    if (value == null) {
      throw new ValidationException("Missing value for required field `" + field + "`");
    }
  }

  /** The first half of ParseKeyNamespaceAndName: the namespace as UTF-8, under 2^16 bytes. */
  public static byte[] parseNamespace(String keyNamespace) {
    return parse(keyNamespace, "Key namespace");
  }

  /** The second half of ParseKeyNamespaceAndName: the name as UTF-8, under 2^16 bytes. */
  public static byte[] parseName(String keyName) {
    return parse(keyName, "Key name");
  }

  /** ErrorMessages.IncorrectRawDataKeys. */
  public static String incorrectRawDataKeys(int index, String keyringName, String keyProviderId) {
    return "EncryptedDataKey " + index + " did not match " + keyringName + ". Expected: keyProviderId: " + keyProviderId + ".\n";
  }

  /**
   * ErrorMessages.IncorrectDataKeys: each key's provider id and provider info (as UTF-8),
   * and for a hierarchical keyring's key its branch key version.
   *
   * @throws ValidationException if a provider info is not UTF-8 or a hierarchical keyring's key is too short
   */
  public static String incorrectDataKeys(List<EncryptedDataKey> encryptedDataKeys, AlgorithmSuite suite) {
    StringBuilder message = new StringBuilder(INCORRECT_DATA_KEYS);
    for (EncryptedDataKey edk : encryptedDataKeys) {
      message.append("KeyProviderId: ").append(edk.keyProviderId()).append(", KeyProviderInfo: ").append(decode(edk.keyProviderInfo()));
      if (edk.keyProviderId().equals(HIERARCHY_PROVIDER_ID)) {
        byte[] wrapped = EdkWrapping.providerWrappedMaterial(edk.ciphertext(), suite);
        if (wrapped.length < BRANCH_KEY_VERSION_INDEX + BRANCH_KEY_VERSION_LENGTH) {
          throw new ValidationException("Incorrect ciphertext structure.");
        }
        ByteBuffer version = ByteBuffer.wrap(wrapped, BRANCH_KEY_VERSION_INDEX, BRANCH_KEY_VERSION_LENGTH);
        message.append(", BranchKeyVersion: ").append(new UUID(version.getLong(), version.getLong()));
      }
      message.append("\n");
    }
    return message.toString();
  }

  // Provider info as text when it is UTF-8, else as hex: a key from another keyring (Raw AES info is binary)
  // must not turn "no matching key" into a decoding failure.
  private static String decode(byte[] bytes) {
    try {
      return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString();
    } catch (CharacterCodingException e) {
      StringBuilder hex = new StringBuilder("0x");
      for (byte b : bytes) {
        hex.append(String.format("%02x", b & 0xff));
      }
      return hex.toString();
    }
  }

  /** UTF8.Decode, strict: malformed input fails with the Dafny runtime's message. */
  public static String decodeUtf8(byte[] bytes) {
    try {
      return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString();
    } catch (CharacterCodingException e) {
      throw new ValidationException(UTF8_FAILURE, e);
    }
  }

  private static byte[] parse(String value, String label) {
    if (!Utf8.isEncodable(value)) {
      throw new ValidationException(label + " could not be UTF8-encoded" + UTF8_FAILURE);
    }
    byte[] bytes = Utf8.encode(value);
    if (bytes.length >= UINT16_LIMIT) {
      throw new ValidationException(label + " too long");
    }
    return bytes;
  }
}
