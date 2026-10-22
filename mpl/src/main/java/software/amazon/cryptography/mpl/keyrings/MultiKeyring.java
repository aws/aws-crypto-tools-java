// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnDecryptResponse;
import software.amazon.cryptography.mpl.OnEncryptRequest;
import software.amazon.cryptography.mpl.OnEncryptResponse;
import software.amazon.cryptography.mpl.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.mpl.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.MaterialsAccess;
import software.amazon.cryptography.mpl.internal.MaterialsRules;

/**
 * Combines keyrings: the generator creates the data key and every child adds an encrypted copy; decryption tries each in turn.
 * Every keyring's result is checked against its input.
 * Thread-safe if its keyrings are.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/multi-keyring.md">Multi-keyring</a>.
 */
// The Dafny-based MPL skipped the result checks for its own keyrings, whose results were proven valid;
// those checks always pass for the built-in keyrings here.
public final class MultiKeyring implements Keyring {

  private final Keyring generator;
  private final List<Keyring> childKeyrings;

  private MultiKeyring(Builder builder) {
    this.generator = builder.generator;
    this.childKeyrings = Collections.unmodifiableList(new ArrayList<>(builder.childKeyrings));
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
  public OnEncryptResponse onEncrypt(OnEncryptRequest request) {
    EncryptionMaterials materials = request.materials();
    boolean hasDataKey = materials.plaintextDataKey().isPresent();
    //= spec/framework/multi-keyring.md#onencrypt
    //= type=implication
    //# If this keyring does not have a [generator keyring](#generator-keyring),
    //# and the input [encryption materials](structures.md#encryption-
    //# materials) does not include a plaintext data key, OnEncrypt MUST
    //# fail.
    if (generator == null && !hasDataKey) {
      throw new ValidationException(
        "Need either a generator keyring or input encryption materials which contain a plaintext data key"
      );
    }
    EncryptionMaterials current = materials;
    //= spec/framework/multi-keyring.md#onencrypt
    //# If this keyring has a generator keyring, this keyring MUST first
    //# generate a plaintext data key using the generator keyring:
    if (generator != null) {
      //= spec/framework/multi-keyring.md#onencrypt
      //= type=implication
      //# - If the input encryption materials already include a plaintext data
      //# key, OnEncrypt MUST fail.
      if (hasDataKey) {
        throw new ValidationException(
          "This multi keyring has a generator but provided Encryption Materials already contain plaintext data key"
        );
      }
      //= spec/framework/multi-keyring.md#onencrypt
      //# - This keyring MUST first call the generator keyring's OnEncrypt
      //# using the input encryption materials as input.
      //= spec/framework/multi-keyring.md#onencrypt
      //# - If the generator keyring fails OnEncrypt, this OnEncrypt MUST also
      //# fail.
      EncryptionMaterials generated = generator.onEncrypt(OnEncryptRequest.builder().materials(current).build()).materials();
      //= spec/framework/multi-keyring.md#onencrypt
      //# - If the generator keyring returns encryption materials missing a
      //# plaintext data key, OnEncrypt MUST fail.
      //= spec/framework/multi-keyring.md#generator-keyring
      //= type=implication
      //# This means that this keyring MUST return
      //# [encryption materials](structures.md#encryption-materials) containing
      //# a plaintext data key on [OnEncrypt](keyring-interface.md#onencrypt).
      requireEncryptTransition(current, generated, "Generator keyring returned invalid encryption materials");
      current = generated;
    }
    for (Keyring child : childKeyrings) {
      OnEncryptResponse response;
      try {
        //= spec/framework/multi-keyring.md#onencrypt
        //# Next, for each [keyring](keyring-interface.md) in this keyring's list
        //# of [child keyrings](#child-keyrings), the keyring MUST call [OnEncrypt]
        //# (keyring-interface.md#onencrypt).
        response = child.onEncrypt(OnEncryptRequest.builder().materials(current).build());
      } catch (RuntimeException e) {
        //= spec/framework/multi-keyring.md#onencrypt
        //# If the child keyring's [OnEncrypt](keyring-
        //# interface.md#onencrypt) fails, this OnEncrypt MUST also fail.
        throw new InvalidMaterialsException("Child keyring failed to encrypt plaintext data key", e);
      }
      // Read outside the try: a null response is a NullPointerException, not a child failure.
      EncryptionMaterials next = response.materials();
      requireEncryptTransition(current, next, "Child keyring performed invalid transition on encryption materials");
      // Intermediate results are this keyring's own; the caller's materials are not.
      if (current != materials && current != next) {
        current.destroy();
      }
      current = next;
    }
    //= spec/framework/multi-keyring.md#onencrypt
    //# If all previous [OnEncrypt](keyring-interface.md#onencrypt) calls
    //# succeeded, this keyring MUST return the [encryption materials]
    //# (structures.md#encryption-materials) returned by the last OnEncrypt
    //# call.
    return OnEncryptResponse.builder().materials(current).build();
  }

  @Override
  public OnDecryptResponse onDecrypt(OnDecryptRequest request) {
    DecryptionMaterials materials = request.materials();
    MaterialsRules.Decryption fields = MaterialsAccess.fields(materials);
    //= spec/framework/multi-keyring.md#ondecrypt
    //= type=implication
    //# If the decryption materials already contain a plaintext data key, the
    //# keyring MUST fail and MUST NOT modify the [decryption materials]
    //# (structures.md#decryption-materials).
    if (fields.plaintextDataKey != null || !MaterialsRules.isValid(fields)) {
      throw new InvalidMaterialsException("Keyring received decryption materials that already contain a plaintext data key.");
    }
    List<Throwable> failures = new ArrayList<>();
    List<Keyring> keyrings = new ArrayList<>();
    if (generator != null) {
      //= spec/framework/multi-keyring.md#ondecrypt
      //# Otherwise, OnDecrypt MUST first attempt to decrypt the [encrypted data
      //# keys](structures.md#encrypted-data-keys-1) in the input [decryption
      //# materials](structures.md#decryption-materials) using its [generator
      //# keyring](#generator-keyring).
      keyrings.add(generator);
    }
    //= spec/framework/multi-keyring.md#ondecrypt
    //# If the generator keyring is unable to
    //# decrypt the materials, the multi-keyring MUST attempt to decrypt
    //# using its child keyrings, until one either succeeds in decryption or
    //# all have failed.
    keyrings.addAll(childKeyrings);
    for (Keyring keyring : keyrings) {
      DecryptionMaterials decrypted;
      try {
        //= spec/framework/multi-keyring.md#ondecrypt
        //# For each [keyring](keyring-interface.md) to be used for decryption,
        //# the multi-keyring MUST call that keyring's [OnDecrypt](keyring-
        //# interface.md#ondecrypt) using the unmodified [decryption materials]
        //# (structures.md#decryption-materials) and the input [encrypted data key]
        //# (structures.md#encrypted-data-key) list.
        decrypted = keyring.onDecrypt(request).materials();
        if (!MaterialsRules.isValidTransition(fields, MaterialsAccess.fields(decrypted))) {
          throw new InvalidMaterialsException("Keyring performed invalid material transition");
        }
      } catch (RuntimeException e) {
        //= spec/framework/multi-keyring.md#ondecrypt
        //# If the child keyring's OnDecrypt call fails, the multi-
        //# keyring MUST collect the error and continue to the next keyring, if
        //# any.
        failures.add(e);
        continue;
      }
      //= spec/framework/multi-keyring.md#ondecrypt
      //# If [OnDecrypt](keyring-
      //# interface.md#ondecrypt) returns [decryption materials]
      //# (structures.md#decryption-materials) containing a plaintext data key,
      //# the multi-keyring MUST immediately return the modified decryption
      //# materials.
      return OnDecryptResponse.builder().materials(decrypted).build();
    }
    //= spec/framework/multi-keyring.md#ondecrypt
    //= type=exception
    //= reason=The failure carries the collected failures in failures() and as suppressed exceptions; its message is the fixed no-match text.
    //# If, after calling [OnDecrypt](keyring-interface.md#ondecrypt) on every
    //# [child keyring](#child-keyrings) (and possibly the [generator keyring]
    //# (#generator-keyring)), the [decryption materials](structures.md#decryption-
    //# materials) still do not contain a plaintext data key, OnDecrypt MUST
    //# return a failure message containing the collected failure messages
    //# from the child keyrings.
    throw new NoMatchingDataKeyException(
      "No Configured Keyring was able to decrypt the Data Key. The list of encountered Exceptions is available via `list`.",
      failures
    );
  }

  private static void requireEncryptTransition(EncryptionMaterials previous, EncryptionMaterials next, String message) {
    MaterialsRules.Encryption nextFields = MaterialsAccess.fields(next);
    if (!MaterialsRules.isReadyForEncrypt(nextFields)) {
      throw new InvalidMaterialsException("Could not retrieve materials required for encryption");
    }
    if (!MaterialsRules.isValidTransition(MaterialsAccess.fields(previous), nextFields)) {
      throw new InvalidMaterialsException(message);
    }
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
      //= spec/framework/multi-keyring.md#inputs
      //= type=implication
      //# On keyring initialization, a keyring MUST define at least one of the
      //# following:
      //= spec/framework/multi-keyring.md#generator-keyring
      //= type=implication
      //# If the list of [child keyrings](#child-keyrings) is empty, a [generator
      //# keyring](#generator-keyring) MUST be defined for the keyring.
      //= spec/framework/multi-keyring.md#child-keyrings
      //= type=implication
      //# If this keyring does not have a [generator keyring](#generator-keyring),
      //# this list MUST NOT be empty.
      if (generator == null && childKeyrings.isEmpty()) {
        throw new ValidationException("Must include a generator keyring and/or at least one child keyring");
      }
      return new MultiKeyring(this);
    }
  }
}
