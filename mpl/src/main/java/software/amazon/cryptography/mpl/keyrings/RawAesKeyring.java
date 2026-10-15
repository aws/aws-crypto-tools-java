// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnEncryptRequest;
import software.amazon.cryptography.mpl.SecretBytes;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

/**
 * Wraps data keys with a local AES-GCM key.
 *
 * <p>Each encrypted data key has provider id = key namespace, provider info =
 * {@code keyName || uint32 tag bits (128) || uint32 IV length (12) || IV}, and ciphertext = {@code AES-GCM ciphertext || tag};
 * the AAD is the canonical encryption context. Thread-safe.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/raw-aes-keyring.md">Raw AES keyring</a>.
 */
public final class RawAesKeyring implements Keyring {

  private final String keyNamespace;
  private final String keyName;
  private final byte[] keyNameBytes;
  private final SecretBytes wrappingKey;
  private final AesWrappingAlg wrappingAlg;

  private RawAesKeyring(Builder builder, byte[] keyNameBytes) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Recorded in each encrypted data key; with keyName identifies the wrapping key. Not {@code aws-kms}. */
  public String keyNamespace() {
    return keyNamespace;
  }

  /** Recorded in each encrypted data key; with keyNamespace identifies the wrapping key. */
  public String keyName() {
    return keyName;
  }

  /** Must match the wrapping key length. */
  public AesWrappingAlg wrappingAlg() {
    return wrappingAlg;
  }

  @Override
  //= spec/framework/raw-aes-keyring.md#onencrypt
  //= type=implication
  //# OnEncrypt MUST take [encryption materials](structures.md#encryption-
  //# materials) as input.
  public EncryptionMaterials onEncrypt(OnEncryptRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  @Override
  //= spec/framework/raw-aes-keyring.md#ondecrypt
  //= type=implication
  //# OnDecrypt MUST take [decryption materials](structures.md#decryption-
  //# materials) and a list of [encrypted data keys]
  //# (structures.md#encrypted-data-key) as input.
  public DecryptionMaterials onDecrypt(OnDecryptRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /**
   * Not thread-safe.
   * Requires {@code keyNamespace}, {@code keyName}, {@code wrappingKey}, {@code wrappingAlg}.
   * {@link #build()} throws {@link ValidationException} for invalid settings.
   */
  //= spec/framework/raw-aes-keyring.md#initialization
  //= type=implication
  //# On keyring initialization, the caller MUST provide the following:
  public static final class Builder {

    private String keyNamespace;
    private String keyName;
    private SecretBytes wrappingKey;
    private AesWrappingAlg wrappingAlg;

    private Builder() {}

    /** Recorded in each encrypted data key; with keyName identifies the wrapping key. Not {@code aws-kms}. */
    public Builder keyNamespace(String keyNamespace) {
      this.keyNamespace = keyNamespace;
      return this;
    }

    /** Recorded in each encrypted data key; with keyNamespace identifies the wrapping key. */
    public Builder keyName(String keyName) {
      this.keyName = keyName;
      return this;
    }

    /** The AES key; {@link #build()} copies it. */
    public Builder wrappingKey(SecretBytes wrappingKey) {
      this.wrappingKey = wrappingKey;
      return this;
    }

    /** Must match the wrapping key length. */
    public Builder wrappingAlg(AesWrappingAlg wrappingAlg) {
      this.wrappingAlg = wrappingAlg;
      return this;
    }

    public RawAesKeyring build() {
      throw new UnsupportedOperationException("not implemented yet");
    }
  }
}
