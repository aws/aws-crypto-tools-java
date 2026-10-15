// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl;

import java.util.Arrays;
import java.util.Objects;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.Utf8;

//= spec/framework/structures.md#structure
//= type=implication
//# An encrypted data key is comprised of the following fields:
//#
//# - [Key Provider ID](#key-provider-id)
//# - [Key Provider Information](#key-provider-information)
//# - [Ciphertext](#ciphertext)
//#
//# Note: "Encrypted" is a misnomer here, as the process by which a key provider may obtain the plaintext data key
//# from the ciphertext and vice versa does not have to be an encryption and decryption cipher.
//# This specification uses the terms "encrypt" and "decrypt" for simplicity,
//# but the actual process by which a key provider obtains the plaintext data key from the ciphertext
//# and vice versa MAY be any reversible operation, though we expect that most will use encryption.
//
//= spec/framework/structures.md#structure
//= type=exception
//= reason=How the ciphertext relates to the data key is the keyring's choice; this type does not constrain it.
//# This specification uses the terms "encrypt" and "decrypt" for simplicity,
//# but the actual process by which a key provider obtains the plaintext data key from the ciphertext
//# and vice versa MAY be any reversible operation, though we expect that most will use encryption.
//
//= spec/framework/structures.md#ciphertext
//= type=exception
//= reason=Only the built-in keyrings can be held to this; a custom keyring may produce any ciphertext.
//# Some key provider MUST be capable of deterministically obtaining the plaintext key from the ciphertext.
/**
 * A data key encrypted by one keyring, as stored in a message.
 * Immutable; {@code equals} compares all three fields; {@code toString} shows the provider id and field lengths.
 */
public final class EncryptedDataKey {

  private final String keyProviderId;
  private final byte[] keyProviderInfo;
  private final byte[] ciphertext;

  private EncryptedDataKey(String keyProviderId, byte[] keyProviderInfo, byte[] ciphertext) {
    this.keyProviderId = keyProviderId;
    this.keyProviderInfo = keyProviderInfo;
    this.ciphertext = ciphertext;
  }

  /**
   * @param keyProviderId text identifying the keyring kind, for example {@code aws-kms}; a message stores it as UTF-8
   * @throws ValidationException if {@code keyProviderId} is not well-formed UTF-16 (a lone surrogate), so it has no UTF-8 form
   */
  public static EncryptedDataKey of(String keyProviderId, byte[] keyProviderInfo, byte[] ciphertext) {
    if (!Utf8.isEncodable(Objects.requireNonNull(keyProviderId, "keyProviderId"))) {
      throw new ValidationException("Key provider id must be well-formed UTF-16");
    }
    return new EncryptedDataKey(keyProviderId, keyProviderInfo.clone(), ciphertext.clone());
  }

  /**
   * An encrypted data key read as a message stores it, with the provider id as UTF-8 bytes. All three arrays are copied.
   *
   * @throws ValidationException if {@code keyProviderId} is not well-formed UTF-8
   */
  public static EncryptedDataKey ofUtf8(byte[] keyProviderId, byte[] keyProviderInfo, byte[] ciphertext) {
    String id = Utf8.decode(keyProviderId);
    if (id == null) {
      throw new ValidationException("Key provider id must be well-formed UTF-8");
    }
    return of(id, keyProviderInfo, ciphertext);
  }

  public String keyProviderId() {
    return keyProviderId;
  }

  /** {@link #keyProviderId()} as the UTF-8 bytes a message stores. A new array on every call. */
  public byte[] keyProviderIdUtf8() {
    return Utf8.encode(keyProviderId);
  }

  /** A copy. */
  public byte[] keyProviderInfo() {
    return keyProviderInfo.clone();
  }

  /** A copy. */
  public byte[] ciphertext() {
    return ciphertext.clone();
  }

  @Override
  public boolean equals(Object other) {
    if (!(other instanceof EncryptedDataKey)) {
      return false;
    }
    EncryptedDataKey that = (EncryptedDataKey) other;
    return (
      keyProviderId.equals(that.keyProviderId) &&
      Arrays.equals(keyProviderInfo, that.keyProviderInfo) &&
      Arrays.equals(ciphertext, that.ciphertext)
    );
  }

  @Override
  public int hashCode() {
    return Objects.hash(keyProviderId, Arrays.hashCode(keyProviderInfo), Arrays.hashCode(ciphertext));
  }

  @Override
  public String toString() {
    return (
      "EncryptedDataKey[" + keyProviderId + ", info " + keyProviderInfo.length + " bytes, ciphertext " + ciphertext.length + " bytes]"
    );
  }
}
