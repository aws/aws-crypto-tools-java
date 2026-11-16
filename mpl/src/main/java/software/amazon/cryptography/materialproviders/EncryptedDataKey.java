// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import java.util.Arrays;
import java.util.Objects;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.internal.Utf8;

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
 * A data key encrypted by one keyring, as stored in a message. Build one with {@link #builder()}.
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

  public static Builder builder() {
    return new Builder();
  }

  /** A builder holding this key's values. */
  public Builder toBuilder() {
    return new Builder().keyProviderId(keyProviderId).keyProviderInfo(keyProviderInfo).ciphertext(ciphertext);
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

  /** Not thread-safe. Requires a key provider id, key provider info and ciphertext; arrays are copied in. */
  public static final class Builder {

    private String keyProviderId;
    private byte[] keyProviderIdUtf8;
    private byte[] keyProviderInfo;
    private byte[] ciphertext;

    private Builder() {}

    /** Text identifying the keyring kind, for example {@code aws-kms}; a message stores it as UTF-8. */
    public Builder keyProviderId(String keyProviderId) {
      this.keyProviderId = keyProviderId;
      this.keyProviderIdUtf8 = null;
      return this;
    }

    /** The provider id as the UTF-8 bytes a message stores; replaces {@link #keyProviderId(String)}. */
    public Builder keyProviderIdUtf8(byte[] keyProviderIdUtf8) {
      this.keyProviderIdUtf8 = keyProviderIdUtf8 == null ? null : keyProviderIdUtf8.clone();
      this.keyProviderId = null;
      return this;
    }

    public Builder keyProviderInfo(byte[] keyProviderInfo) {
      this.keyProviderInfo = keyProviderInfo == null ? null : keyProviderInfo.clone();
      return this;
    }

    public Builder ciphertext(byte[] ciphertext) {
      this.ciphertext = ciphertext == null ? null : ciphertext.clone();
      return this;
    }

    /**
     * @throws ValidationException if a member is missing, if the provider id is not well-formed UTF-16 (a lone
     *     surrogate, so it has no UTF-8 form), or if the bytes given to {@link #keyProviderIdUtf8(byte[])} are not UTF-8
     */
    public EncryptedDataKey build() {
      String id = keyProviderId;
      if (keyProviderIdUtf8 != null) {
        id = Utf8.decode(keyProviderIdUtf8);
        if (id == null) {
          throw new ValidationException("Key provider id must be well-formed UTF-8");
        }
      }
      if (id == null) {
        throw new ValidationException("Missing value for required field `keyProviderId`");
      }
      if (keyProviderInfo == null) {
        throw new ValidationException("Missing value for required field `keyProviderInfo`");
      }
      if (ciphertext == null) {
        throw new ValidationException("Missing value for required field `ciphertext`");
      }
      if (!Utf8.isEncodable(id)) {
        throw new ValidationException("Key provider id must be well-formed UTF-16");
      }
      return new EncryptedDataKey(id, keyProviderInfo.clone(), ciphertext.clone());
    }
  }
}
