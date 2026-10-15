// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl;

/**
 * Generates, encrypts, and decrypts data keys.
 *
 * <p>Implement this to plug in a custom key source. Implementations must be thread-safe.
 * The built-in managers and {@link software.amazon.cryptography.mpl.keyrings.MultiKeyring} check every result
 * against its input.
 * A manager the caller writes that calls a keyring itself should check the result with
 * {@link EncryptionMaterials#isValidTransitionFrom} or {@link DecryptionMaterials#isValidTransitionFrom}.
 * An exception an implementation throws reaches the caller unchanged,
 * except inside a {@link software.amazon.cryptography.mpl.keyrings.MultiKeyring}: a failed decrypt there reports every
 * child's exception in {@link software.amazon.cryptography.mpl.exceptions.NoMatchingDataKeyException#failures()}.
 *
 * <p>The caller owns the materials a keyring returns, which hold their own copies of the secrets;
 * the materials passed in stay with whoever passed them.
 *
 * <p>Each method takes a request object,
 * so a later version can add request fields without breaking keyrings that callers implement.
 *
 * <p>Not {@link AutoCloseable}: most keyrings hold nothing to release.
 * The KMS multi and discovery multi keyrings can create their own clients; close those keyrings through their own type.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/keyring-interface.md">keyring interface</a>.
 */
public interface Keyring {
  /**
   * Returns the request's materials with a plaintext data key (generated here if absent) and this keyring's
   * encrypted copy of it added.
   */
  //= spec/framework/keyring-interface.md#onencrypt
  //= type=implication
  //# This interface MUST take [encryption materials](structures.md#encryption-materials) as input.
  //= spec/framework/keyring-interface.md#onencrypt
  //= type=implication
  //# It MUST modify it with at least one of the following behaviors:
  //# - [Generate data key](#generate-data-key)
  //# - [Encrypt data key](#encrypt-data-key)
  //# If this keyring attempted any of the above behaviors, and successfully completed those behaviors,
  //# it MUST output the modified [encryption materials](structures.md#encryption-materials).
  EncryptionMaterials onEncrypt(OnEncryptRequest request);

  /**
   * Returns the request's materials with the plaintext data key from the first of its encrypted data keys
   * this keyring can decrypt.
   *
   * @throws software.amazon.cryptography.mpl.exceptions.NoMatchingDataKeyException if it can decrypt none
   */
  //= spec/framework/keyring-interface.md#ondecrypt
  //= type=implication
  //# This interface MUST take [decryption materials](structures.md#decryption-materials) and
  //# a list of [encrypted data keys](structures.md#encrypted-data-key) as input.
  //= spec/framework/keyring-interface.md#ondecrypt
  //= type=implication
  //# It MUST modify it with the following behavior:
  //#
  //# - [Decrypt data key](#decrypt-data-key)
  //#
  //# If the decryption materials already contain a plaintext data key,
  //# the keyring MUST fail
  //# and MUST NOT modify the [decryption materials](structures.md#decryption-materials).
  //#
  //# If this keyring attempted the above behavior, and succeeded, it MUST output the modified [decryption materials](structures.md#decryption-materials).
  DecryptionMaterials onDecrypt(OnDecryptRequest request);
}
