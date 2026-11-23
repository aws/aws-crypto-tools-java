// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keystore;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.internal.KeyMaterialsAccess;

//= spec/framework/structures.md#structure-4
//= type=implication
//# This structure MUST include the following fields:
//# - [Beacon Key Id](#beacon-key-id)
//# - [Encryption Context](#encryption-context-4)
//
//= spec/framework/structures.md#structure-4
//= type=implication
//# This structure MAY include the following fields:
//# - [Beacon Key](#beacon-key)
//# - [HMAC Keys](#hmac-keys)
/** The beacon key of a branch key, used by the AWS Database Encryption SDK. Immutable. */
public final class BeaconKeyMaterials {

  static {
    KeyMaterialsAccess.registerBeaconKey(BeaconKeyMaterials::new);
  }

  private final String beaconKeyIdentifier;
  private final EncryptionContext encryptionContext;
  private final SecretBytes beaconKey;
  private final Map<String, SecretBytes> hmacKeys;

  private BeaconKeyMaterials(
    String beaconKeyIdentifier,
    EncryptionContext encryptionContext,
    SecretBytes beaconKey,
    Map<String, SecretBytes> hmacKeys
  ) {
    this.beaconKeyIdentifier = Objects.requireNonNull(beaconKeyIdentifier, "beaconKeyIdentifier");
    this.encryptionContext = Objects.requireNonNull(encryptionContext, "encryptionContext");
    this.beaconKey = beaconKey;
    Map<String, SecretBytes> copy = new LinkedHashMap<>();
    for (Map.Entry<String, SecretBytes> entry : hmacKeys.entrySet()) {
      copy.put(Objects.requireNonNull(entry.getKey(), "hmac key name"), Objects.requireNonNull(entry.getValue(), "hmac key"));
    }
    this.hmacKeys = Collections.unmodifiableMap(copy);
  }

  /** For a {@link KeyStore} implementation that decrypts beacon keys itself. */
  public static Builder builder() {
    return new Builder();
  }

  public String beaconKeyIdentifier() {
    return beaconKeyIdentifier;
  }

  public EncryptionContext encryptionContext() {
    return encryptionContext;
  }

  /** Owned by these materials; read it, do not destroy it. */
  public Optional<SecretBytes> beaconKey() {
    return Optional.ofNullable(beaconKey);
  }

  /** Per-beacon HMAC keys derived from the beacon key; empty when none were derived. Owned by these materials. */
  public Map<String, SecretBytes> hmacKeys() {
    return hmacKeys;
  }

  /**
   * These materials with {@code hmacKeys} in place of the beacon key: the entry a beacon key cache holds,
   * so the cache never holds the beacon key itself.
   * The keys are copied, so the caller keeps ownership of its own.
   */
  public BeaconKeyMaterials toHmacKeysOnly(Map<String, SecretBytes> hmacKeys) {
    // Checked before copying, so a null leaves no copy behind undestroyed.
    for (Map.Entry<String, SecretBytes> entry : hmacKeys.entrySet()) {
      Objects.requireNonNull(entry.getKey(), "hmac key name");
      Objects.requireNonNull(entry.getValue(), "hmac key");
    }
    Map<String, SecretBytes> copies = new LinkedHashMap<>();
    for (Map.Entry<String, SecretBytes> entry : hmacKeys.entrySet()) {
      copies.put(entry.getKey(), entry.getValue().copy());
    }
    return new BeaconKeyMaterials(beaconKeyIdentifier, encryptionContext, null, copies);
  }

  /** Compares every field; the keys by content, in constant time. */
  @Override
  public boolean equals(Object other) {
    if (!(other instanceof BeaconKeyMaterials)) {
      return false;
    }
    BeaconKeyMaterials that = (BeaconKeyMaterials) other;
    if (
      !beaconKeyIdentifier.equals(that.beaconKeyIdentifier) ||
      !encryptionContext.equals(that.encryptionContext) ||
      !hmacKeys.keySet().equals(that.hmacKeys.keySet())
    ) {
      return false;
    }
    if (beaconKey == null ? that.beaconKey != null : that.beaconKey == null || !beaconKey.contentEquals(that.beaconKey)) {
      return false;
    }
    for (Map.Entry<String, SecretBytes> entry : hmacKeys.entrySet()) {
      if (!entry.getValue().contentEquals(that.hmacKeys.get(entry.getKey()))) {
        return false;
      }
    }
    return true;
  }

  @Override
  public int hashCode() {
    return Objects.hash(beaconKeyIdentifier, encryptionContext, hmacKeys.keySet());
  }

  /** Id and context keys; never keys. */
  @Override
  public String toString() {
    return "BeaconKeyMaterials[" + beaconKeyIdentifier + ", context keys " + encryptionContext.keySet() + "]";
  }

  /** Not thread-safe. Requires every member. */
  public static final class Builder {

    private String beaconKeyIdentifier;
    private EncryptionContext encryptionContext;
    private SecretBytes beaconKey;

    private Builder() {}

    public Builder beaconKeyIdentifier(String beaconKeyIdentifier) {
      this.beaconKeyIdentifier = beaconKeyIdentifier;
      return this;
    }

    public Builder encryptionContext(EncryptionContext encryptionContext) {
      this.encryptionContext = encryptionContext;
      return this;
    }

    /** The decrypted beacon key. Copied by {@link #build()}, so the caller keeps ownership of its own. */
    public Builder beaconKey(SecretBytes beaconKey) {
      this.beaconKey = beaconKey;
      return this;
    }

    /** {@link #beaconKey(SecretBytes)} from an array, copied now; zero your own array when you no longer need it. */
    public Builder beaconKey(byte[] beaconKey) {
      return beaconKey(beaconKey == null ? null : SecretBytes.copyOf(beaconKey));
    }

    /** Materials with the beacon key and no HMAC keys, as {@link DynamoDbKeyStore#getBeaconKey} returns them. */
    public BeaconKeyMaterials build() {
      if (beaconKeyIdentifier == null) {
        throw new ValidationException("Missing value for required field `beaconKeyIdentifier`");
      }
      if (encryptionContext == null) {
        throw new ValidationException("Missing value for required field `encryptionContext`");
      }
      if (beaconKey == null) {
        throw new ValidationException("Missing value for required field `beaconKey`");
      }
      return new BeaconKeyMaterials(beaconKeyIdentifier, encryptionContext, beaconKey.copy(), Collections.<String, SecretBytes>emptyMap());
    }
  }
}
