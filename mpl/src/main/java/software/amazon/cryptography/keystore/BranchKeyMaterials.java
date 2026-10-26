// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.keystore;

import java.util.Objects;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.internal.KeyMaterialsAccess;

//= spec/framework/structures.md#structure-3
//= type=implication
//# This structure MUST include all of the following fields:
//#
//# - [Branch Key](#branch-key)
//# - [Branch Key Id](#branch-key-id)
//# - [Branch Key Version](#branch-key-version)
//# - [Encryption Context](#encryption-context-3)
/** One version of a branch key. Immutable. */
public final class BranchKeyMaterials {

  static {
    KeyMaterialsAccess.registerBranchKey(BranchKeyMaterials::new);
  }

  private final String branchKeyIdentifier;
  private final String branchKeyVersion;
  private final EncryptionContext encryptionContext;
  private final SecretBytes branchKey;

  private BranchKeyMaterials(
    String branchKeyIdentifier,
    String branchKeyVersion,
    EncryptionContext encryptionContext,
    SecretBytes branchKey
  ) {
    this.branchKeyIdentifier = Objects.requireNonNull(branchKeyIdentifier, "branchKeyIdentifier");
    this.branchKeyVersion = Objects.requireNonNull(branchKeyVersion, "branchKeyVersion");
    this.encryptionContext = Objects.requireNonNull(encryptionContext, "encryptionContext");
    this.branchKey = Objects.requireNonNull(branchKey, "branchKey");
  }

  public String branchKeyIdentifier() {
    return branchKeyIdentifier;
  }

  /** A UUID string. */
  public String branchKeyVersion() {
    return branchKeyVersion;
  }

  /** The custom encryption context given at creation. */
  public EncryptionContext encryptionContext() {
    return encryptionContext;
  }

  /** Owned by these materials; read it, do not destroy it. */
  public SecretBytes branchKey() {
    return branchKey;
  }

  /** Compares every field; the keys by content, in constant time. */
  @Override
  public boolean equals(Object other) {
    if (!(other instanceof BranchKeyMaterials)) {
      return false;
    }
    BranchKeyMaterials that = (BranchKeyMaterials) other;
    return (
      branchKeyIdentifier.equals(that.branchKeyIdentifier) &&
      branchKeyVersion.equals(that.branchKeyVersion) &&
      encryptionContext.equals(that.encryptionContext) &&
      branchKey.contentEquals(that.branchKey)
    );
  }

  @Override
  public int hashCode() {
    return Objects.hash(branchKeyIdentifier, branchKeyVersion, encryptionContext);
  }

  /** Id, version, and context keys; never the key. */
  @Override
  public String toString() {
    return (
      "BranchKeyMaterials[" + branchKeyIdentifier + ", version " + branchKeyVersion +
      ", context keys " + encryptionContext.keySet() + "]"
    );
  }
}
