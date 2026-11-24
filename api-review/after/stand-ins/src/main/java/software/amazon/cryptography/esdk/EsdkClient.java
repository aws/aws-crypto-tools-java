// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package software.amazon.cryptography.esdk;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.OptionalInt;
import java.util.function.Consumer;
import software.amazon.cryptography.materialproviders.EsdkCommitmentPolicy;

/**
 * Encrypts and decrypts AWS Encryption SDK messages. Thread-safe; holds no resources, so there is
 * nothing to close.
 *
 * <p>Settings that apply to every call (the commitment policy and the cap on encrypted data keys)
 * are set on the client. Everything about one message (the data, the keyring or materials manager,
 * the encryption context, the algorithm suite, the frame length) is set on the request.
 *
 * <p>An interface, as AWS SDK for Java 2.x clients are, so that callers can substitute their own in
 * tests.
 */
public interface EsdkClient {

  /** A client with the default settings: {@code REQUIRE_ENCRYPT_REQUIRE_DECRYPT}, no cap. */
  static EsdkClient create() {
    return builder().build();
  }

  static Builder builder() {
    return new Builder();
  }

  /** Encrypts a plaintext held in memory into an encrypted message. */
  EncryptResponse encrypt(EncryptRequest request);

  /** {@link #encrypt(EncryptRequest)} with a request built by {@code request}. */
  default EncryptResponse encrypt(Consumer<EncryptRequest.Builder> request) {
    EncryptRequest.Builder builder = EncryptRequest.builder();
    request.accept(builder);
    return encrypt(builder.build());
  }

  /**
   * Decrypts an encrypted message held in memory. No plaintext is returned unless the whole
   * message, including any signature, verifies.
   */
  DecryptResponse decrypt(DecryptRequest request);

  /** {@link #decrypt(DecryptRequest)} with a request built by {@code request}. */
  default DecryptResponse decrypt(Consumer<DecryptRequest.Builder> request) {
    DecryptRequest.Builder builder = DecryptRequest.builder();
    request.accept(builder);
    return decrypt(builder.build());
  }

  /**
   * A stream that encrypts what is written to it and writes the encrypted message to {@code
   * ciphertext}. Closing it writes the rest of the message and closes {@code ciphertext}.
   */
  EncryptingOutputStream encryptingStream(EncryptStreamRequest request, OutputStream ciphertext);

  /** {@link #encryptingStream(EncryptStreamRequest, OutputStream)} with a built request. */
  default EncryptingOutputStream encryptingStream(
      Consumer<EncryptStreamRequest.Builder> request, OutputStream ciphertext) {
    EncryptStreamRequest.Builder builder = EncryptStreamRequest.builder();
    request.accept(builder);
    return encryptingStream(builder.build(), ciphertext);
  }

  /**
   * A stream of the plaintext of the encrypted message read from {@code ciphertext}.
   *
   * <p>The stream returns plaintext before the end of the message is verified. Do not act on it
   * until a read returns -1 without throwing.
   */
  DecryptingInputStream decryptingStream(DecryptStreamRequest request, InputStream ciphertext);

  /** {@link #decryptingStream(DecryptStreamRequest, InputStream)} with a built request. */
  default DecryptingInputStream decryptingStream(
      Consumer<DecryptStreamRequest.Builder> request, InputStream ciphertext) {
    DecryptStreamRequest.Builder builder = DecryptStreamRequest.builder();
    request.accept(builder);
    return decryptingStream(builder.build(), ciphertext);
  }

  /** The commitment policy every operation enforces. */
  EsdkCommitmentPolicy commitmentPolicy();

  /** The most encrypted data keys a message may have, if capped. */
  OptionalInt maxEncryptedDataKeys();

  /** Not thread-safe. */
  final class Builder {

    private EsdkCommitmentPolicy commitmentPolicy =
        EsdkCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT;
    private Integer maxEncryptedDataKeys;

    private Builder() {}

    /** Default {@code REQUIRE_ENCRYPT_REQUIRE_DECRYPT}. */
    public Builder commitmentPolicy(EsdkCommitmentPolicy commitmentPolicy) {
      this.commitmentPolicy = commitmentPolicy;
      return this;
    }

    /** Encrypt and decrypt fail for a message with more encrypted data keys. Default: no cap. */
    public Builder maxEncryptedDataKeys(int maxEncryptedDataKeys) {
      this.maxEncryptedDataKeys = maxEncryptedDataKeys;
      return this;
    }

    /** @throws EsdkValidationException if the commitment policy is unset or the cap is below 1 */
    public EsdkClient build() {
      if (commitmentPolicy == null) {
        throw new EsdkValidationException("Missing value for required field `commitmentPolicy`");
      }
      if (maxEncryptedDataKeys != null && maxEncryptedDataKeys < 1) {
        throw new EsdkValidationException("maxEncryptedDataKeys must be positive");
      }
      throw new UnsupportedOperationException("Stand-in: the ESDK 4.0 sketch has no implementation here");
    }
  }
}
