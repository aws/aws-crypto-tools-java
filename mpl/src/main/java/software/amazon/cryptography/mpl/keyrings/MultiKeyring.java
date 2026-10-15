// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnEncryptRequest;
import software.amazon.cryptography.mpl.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

/**
 * Combines keyrings: the generator creates the data key and every child adds an encrypted copy; decryption tries each in turn.
 * Every keyring's result is checked against its input.
 * Thread-safe if its keyrings are.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/multi-keyring.md">Multi-keyring</a>.
 */
public final class MultiKeyring implements Keyring {

  private final Keyring generator;
  private final List<Keyring> childKeyrings;

  private MultiKeyring(Builder builder) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Creates the data key on encrypt. Without it, encryption needs materials that already hold a data key. */
  public Optional<Keyring> generator() {
    return Optional.ofNullable(generator);
  }

  /** Keyrings that each add an encrypted copy. */
  public List<Keyring> childKeyrings() {
    return childKeyrings;
  }

  /**
   * {@inheritDoc}
   *
   * <p>A generator's exception reaches the caller unchanged. A child's is the cause of an
   * {@link InvalidMaterialsException}, so the caller can tell which step failed.
   */
  @Override
  //= spec/framework/multi-keyring.md#generator-keyring
  //= type=implication
  //# This keyring MUST implement the [Generate Data Key](keyring-
  //# interface.md#generate-data-key) behavior during [OnEncrypt](keyring-
  //# interface.md#onencrypt).
  public EncryptionMaterials onEncrypt(OnEncryptRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  @Override
  public DecryptionMaterials onDecrypt(OnDecryptRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /**
   * Not thread-safe.
   * {@link #build()} throws {@link ValidationException} unless there is a generator or at least one child.
   */
  public static final class Builder {

    private Keyring generator;
    private List<Keyring> childKeyrings = new ArrayList<>();

    private Builder() {}

    /** Creates the data key on encrypt. Without it, encryption needs materials that already hold a data key. */
    public Builder generator(Keyring generator) {
      this.generator = generator;
      return this;
    }

    /** Keyrings that each add an encrypted copy, in order. Copied. */
    public Builder childKeyrings(Collection<? extends Keyring> childKeyrings) {
      this.childKeyrings = new ArrayList<>(childKeyrings);
      for (Keyring child : this.childKeyrings) {
        Objects.requireNonNull(child, "child keyring");
      }
      return this;
    }

    public MultiKeyring build() {
      throw new UnsupportedOperationException("not implemented yet");
    }
  }
}
