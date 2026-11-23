// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keystore;

import java.util.Objects;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
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

  private final String branchKeyId;
  private final String branchKeyVersion;
  private final EncryptionContext encryptionContext;
  private final SecretBytes branchKey;

  private BranchKeyMaterials(
    String branchKeyId,
    String branchKeyVersion,
    EncryptionContext encryptionContext,
    SecretBytes branchKey
  ) {
    this.branchKeyId = Objects.requireNonNull(branchKeyId, "branchKeyId");
    this.branchKeyVersion = Objects.requireNonNull(branchKeyVersion, "branchKeyVersion");
    this.encryptionContext = Objects.requireNonNull(encryptionContext, "encryptionContext");
    this.branchKey = Objects.requireNonNull(branchKey, "branchKey");
  }

  /** For a {@link KeyStore} implementation that decrypts branch keys itself. */
  public static Builder builder() {
    return new Builder();
  }

  public String branchKeyId() {
    return branchKeyId;
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
      branchKeyId.equals(that.branchKeyId) &&
      branchKeyVersion.equals(that.branchKeyVersion) &&
      encryptionContext.equals(that.encryptionContext) &&
      branchKey.contentEquals(that.branchKey)
    );
  }

  @Override
  public int hashCode() {
    return Objects.hash(branchKeyId, branchKeyVersion, encryptionContext);
  }

  /** Id, version, and context keys; never the key. */
  @Override
  public String toString() {
    return (
      "BranchKeyMaterials[" + branchKeyId + ", version " + branchKeyVersion +
      ", context keys " + encryptionContext.keySet() + "]"
    );
  }

  /** Not thread-safe. Requires every member. */
  public static final class Builder {

    private String branchKeyId;
    private String branchKeyVersion;
    private EncryptionContext encryptionContext;
    private SecretBytes branchKey;

    private Builder() {}

    public Builder branchKeyId(String branchKeyId) {
      this.branchKeyId = branchKeyId;
      return this;
    }

    /** A UUID string. */
    public Builder branchKeyVersion(String branchKeyVersion) {
      this.branchKeyVersion = branchKeyVersion;
      return this;
    }

    /** The custom encryption context given at creation. */
    public Builder encryptionContext(EncryptionContext encryptionContext) {
      this.encryptionContext = encryptionContext;
      return this;
    }

    /** The decrypted branch key. Copied by {@link #build()}, so the caller keeps ownership of its own. */
    public Builder branchKey(SecretBytes branchKey) {
      this.branchKey = branchKey;
      return this;
    }

    /** {@link #branchKey(SecretBytes)} from an array, copied now; zero your own array when you no longer need it. */
    public Builder branchKey(byte[] branchKey) {
      return branchKey(branchKey == null ? null : SecretBytes.copyOf(branchKey));
    }

    public BranchKeyMaterials build() {
      if (branchKeyId == null) {
        throw new ValidationException("Missing value for required field `branchKeyId`");
      }
      if (branchKeyVersion == null) {
        throw new ValidationException("Missing value for required field `branchKeyVersion`");
      }
      if (encryptionContext == null) {
        throw new ValidationException("Missing value for required field `encryptionContext`");
      }
      if (branchKey == null) {
        throw new ValidationException("Missing value for required field `branchKey`");
      }
      return new BranchKeyMaterials(branchKeyId, branchKeyVersion, encryptionContext, branchKey.copy());
    }
  }
}
