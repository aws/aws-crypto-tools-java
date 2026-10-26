// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.keystore;

import java.util.Map;
import software.amazon.cryptography.materialproviders.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.materialproviders.internal.Utf8;

/** A key read from the store: the KMS encryption context of its item and the plaintext key. */
public final class UnwrappedKey {

  private final Map<String, String> context;
  private final byte[] key;

  UnwrappedKey(Map<String, String> context, byte[] key) {
    this.context = context;
    this.key = key;
  }

  public String branchKeyIdentifier() {
    return context.get(KeyStoreItems.BRANCH_KEY_IDENTIFIER_FIELD);
  }

  /** The version this item stores, which branch key materials carry as UTF-8 (Structure.ToBranchKeyMaterials). */
  //= spec/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context
  //= type=implication
  //# The remaining string encoded as UTF8 bytes MUST be the Branch Key version.
  public String branchKeyVersion() {
    String version = KeyStoreItems.versionOf(context);
    if (!Utf8.isEncodable(version)) {
      throw new InvalidMaterialsException(KeyStoreMessages.VERSION_NOT_UTF8);
    }
    return version;
  }

  /** The caller's encryption context stored with the key, which materials carry as UTF-8. */
  //= spec/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context
  //= type=implication
  //# - [Encryption Context](./structures.md#encryption-context-3) MUST be constructed by
  //# [Custom Encryption Context From Authenticated Encryption Context](#custom-encryption-context-from-authenticated-encryption-context)
  public Map<String, String> encryptionContext() {
    Map<String, String> custom = KeyStoreItems.customContext(context);
    for (Map.Entry<String, String> entry : custom.entrySet()) {
      if (!Utf8.isEncodable(entry.getKey()) || !Utf8.isEncodable(entry.getValue())) {
        throw new InvalidMaterialsException(KeyStoreMessages.CONTEXT_NOT_UTF8);
      }
    }
    return custom;
  }

  /** The plaintext key; the caller takes ownership and clears it. */
  public byte[] key() {
    return key;
  }
}
