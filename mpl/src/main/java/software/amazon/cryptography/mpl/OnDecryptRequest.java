// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

/**
 * Input to {@link Keyring#onDecrypt}. Immutable.
 * Holds the caller's materials, not a copy; they stay with the caller.
 */
public final class OnDecryptRequest {

  private final DecryptionMaterials materials;
  private final List<EncryptedDataKey> encryptedDataKeys;

  private OnDecryptRequest(Builder builder) {
    this.materials = builder.materials;
    this.encryptedDataKeys = Collections.unmodifiableList(builder.encryptedDataKeys);
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this request's values. */
  public Builder toBuilder() {
    return new Builder().materials(materials).encryptedDataKeys(encryptedDataKeys);
  }

  /** The materials to add the plaintext data key to. */
  public DecryptionMaterials materials() {
    return materials;
  }

  /** The encrypted data keys to try, in order. */
  public List<EncryptedDataKey> encryptedDataKeys() {
    return encryptedDataKeys;
  }

  @Override
  public String toString() {
    return "OnDecryptRequest[" + materials + ", " + encryptedDataKeys.size() + " encrypted data keys]";
  }

  /** Not thread-safe. Requires materials and encrypted data keys. */
  public static final class Builder {

    private DecryptionMaterials materials;
    private List<EncryptedDataKey> encryptedDataKeys;

    private Builder() {}

    public Builder materials(DecryptionMaterials materials) {
      this.materials = materials;
      return this;
    }

    /** Copied. */
    public Builder encryptedDataKeys(Collection<EncryptedDataKey> encryptedDataKeys) {
      this.encryptedDataKeys = new ArrayList<>(encryptedDataKeys);
      return this;
    }

    /** The same as {@link #encryptedDataKeys(Collection)}; a null array is a null collection. */
    public Builder encryptedDataKeys(EncryptedDataKey... encryptedDataKeys) {
      return encryptedDataKeys(encryptedDataKeys == null ? null : Arrays.asList(encryptedDataKeys));
    }

    public OnDecryptRequest build() {
      if (materials == null) {
        throw new ValidationException("Missing value for required field `materials`");
      }
      if (encryptedDataKeys == null) {
        throw new ValidationException("Missing value for required field `encryptedDataKeys`");
      }
      return new OnDecryptRequest(this);
    }
  }
}
