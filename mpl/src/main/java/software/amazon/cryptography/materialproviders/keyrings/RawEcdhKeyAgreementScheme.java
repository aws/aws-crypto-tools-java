// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keyrings;

import java.security.PrivateKey;
import java.security.PublicKey;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.internal.KeyringNames;
import software.amazon.cryptography.materialproviders.internal.primitives.Pem;

/**
 * Which keys a {@link RawEcdhKeyring} holds. Build one with the builder each static method returns; there are no other kinds.
 * Private keys are UTF-8 PEM (PKCS #8); public keys are DER (X.509 SubjectPublicKeyInfo); both are copied.
 * The setters that take JCA keys encode them that way, so a keyring behaves as with those bytes;
 * they throw {@link ValidationException} for a key with no encoding.
 * {@code build()} throws {@link ValidationException} for a missing key; {@link RawEcdhKeyring.Builder#build()} checks the keys themselves.
 * Immutable.
 */
public abstract class RawEcdhKeyAgreementScheme {

  /** The kinds, for {@code switch}. More constants may be added; a {@code switch} needs a {@code default} branch. */
  public enum Kind {
    RAW_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY,
    EPHEMERAL_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY,
    PUBLIC_KEY_DISCOVERY,
  }

  private final SecretBytes privateKey;
  private final byte[] recipientPublicKey;

  private RawEcdhKeyAgreementScheme(SecretBytes privateKey, byte[] recipientPublicKey) {
    this.privateKey = privateKey;
    this.recipientPublicKey = recipientPublicKey;
  }

  /** A fixed sender key pair and recipient public key; encrypts and decrypts. Requires both keys. */
  public static RawPrivateKeyToStaticPublicKeyBuilder rawPrivateKeyToStaticPublicKey() {
    return new RawPrivateKeyToStaticPublicKeyBuilder();
  }

  /** A new sender key pair per message; encrypts only. Requires the recipient's public key. */
  public static EphemeralPrivateKeyToStaticPublicKeyBuilder ephemeralPrivateKeyToStaticPublicKey() {
    return new EphemeralPrivateKeyToStaticPublicKeyBuilder();
  }

  /** The recipient's private key; decrypts any message addressed to it, encrypts nothing. Requires the private key. */
  public static PublicKeyDiscoveryBuilder publicKeyDiscovery() {
    return new PublicKeyDiscoveryBuilder();
  }

  public abstract Kind kind();

  /** The sender's static private key, or for discovery the recipient's; null for ephemeral. Not a copy. */
  SecretBytes privateKey() {
    return privateKey;
  }

  /** Null for discovery. Not a copy. */
  byte[] recipientPublicKey() {
    return recipientPublicKey;
  }

  // A builder's private key. The caller owns a SecretBytes it sets; the builder owns the copy it makes of a byte[] or JCA key,
  // and destroys that copy when the key is replaced. Null is a missing key; build() copies whichever is set.
  private static final class PrivateKeySetting {

    private SecretBytes key;
    private boolean owned;

    void caller(SecretBytes key) {
      replace(key, false);
    }

    void copyOf(byte[] key) {
      replace(key == null ? null : SecretBytes.copyOf(key), key != null);
    }

    void encode(PrivateKey key, String name) {
      replace(key == null ? null : Pem.privateKey(key, name), key != null);
    }

    private void replace(SecretBytes next, boolean ownsNext) {
      if (owned) {
        key.destroy();
      }
      key = next;
      owned = ownsNext;
    }
  }

  private static byte[] publicKey(byte[] key) {
    return key == null ? null : key.clone();
  }

  private static byte[] publicKey(PublicKey key, String name) {
    return key == null ? null : Pem.encoded(key, name).clone();
  }

  /**
   * Not thread-safe. A key set as {@code byte[]} or {@code PrivateKey} is copied into the builder, which keeps that copy
   * until the key is set again or the builder is garbage collected.
   */
  public static final class RawPrivateKeyToStaticPublicKeyBuilder {

    private final PrivateKeySetting senderStaticPrivateKey = new PrivateKeySetting();
    private byte[] recipientPublicKey;

    private RawPrivateKeyToStaticPublicKeyBuilder() {}

    /** The sender's private key; {@link #build()} copies it. */
    public RawPrivateKeyToStaticPublicKeyBuilder senderStaticPrivateKey(SecretBytes senderStaticPrivateKey) {
      this.senderStaticPrivateKey.caller(senderStaticPrivateKey);
      return this;
    }

    /** {@link #senderStaticPrivateKey(SecretBytes)} from an array, copied now; zero your own array when you no longer need it. */
    public RawPrivateKeyToStaticPublicKeyBuilder senderStaticPrivateKey(byte[] senderStaticPrivateKey) {
      this.senderStaticPrivateKey.copyOf(senderStaticPrivateKey);
      return this;
    }

    /** {@link #senderStaticPrivateKey(SecretBytes)} with a JCA key, encoded now. */
    public RawPrivateKeyToStaticPublicKeyBuilder senderStaticPrivateKey(PrivateKey senderStaticPrivateKey) {
      this.senderStaticPrivateKey.encode(senderStaticPrivateKey, "senderStaticPrivateKey");
      return this;
    }

    public RawPrivateKeyToStaticPublicKeyBuilder recipientPublicKey(byte[] recipientPublicKey) {
      this.recipientPublicKey = publicKey(recipientPublicKey);
      return this;
    }

    public RawPrivateKeyToStaticPublicKeyBuilder recipientPublicKey(PublicKey recipientPublicKey) {
      this.recipientPublicKey = publicKey(recipientPublicKey, "recipientPublicKey");
      return this;
    }

    /** @throws ValidationException if a key is missing */
    public RawEcdhKeyAgreementScheme build() {
      KeyringNames.requireSet(senderStaticPrivateKey.key, "senderStaticPrivateKey");
      KeyringNames.requireSet(recipientPublicKey, "recipientPublicKey");
      return new Of(Kind.RAW_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY, senderStaticPrivateKey.key.copy(), recipientPublicKey.clone());
    }
  }

  /** Not thread-safe. */
  public static final class EphemeralPrivateKeyToStaticPublicKeyBuilder {

    private byte[] recipientPublicKey;

    private EphemeralPrivateKeyToStaticPublicKeyBuilder() {}

    public EphemeralPrivateKeyToStaticPublicKeyBuilder recipientPublicKey(byte[] recipientPublicKey) {
      this.recipientPublicKey = publicKey(recipientPublicKey);
      return this;
    }

    public EphemeralPrivateKeyToStaticPublicKeyBuilder recipientPublicKey(PublicKey recipientPublicKey) {
      this.recipientPublicKey = publicKey(recipientPublicKey, "recipientPublicKey");
      return this;
    }

    /** @throws ValidationException if the key is missing */
    public RawEcdhKeyAgreementScheme build() {
      KeyringNames.requireSet(recipientPublicKey, "recipientPublicKey");
      return new Of(Kind.EPHEMERAL_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY, null, recipientPublicKey.clone());
    }
  }

  /** Not thread-safe. Keeps its copy of a key set as {@code byte[]} or {@code PrivateKey}, as the static key builder does. */
  public static final class PublicKeyDiscoveryBuilder {

    private final PrivateKeySetting recipientStaticPrivateKey = new PrivateKeySetting();

    private PublicKeyDiscoveryBuilder() {}

    /** The recipient's private key; {@link #build()} copies it. */
    public PublicKeyDiscoveryBuilder recipientStaticPrivateKey(SecretBytes recipientStaticPrivateKey) {
      this.recipientStaticPrivateKey.caller(recipientStaticPrivateKey);
      return this;
    }

    /** {@link #recipientStaticPrivateKey(SecretBytes)} from an array, copied now; zero your own array when you no longer need it. */
    public PublicKeyDiscoveryBuilder recipientStaticPrivateKey(byte[] recipientStaticPrivateKey) {
      this.recipientStaticPrivateKey.copyOf(recipientStaticPrivateKey);
      return this;
    }

    /** {@link #recipientStaticPrivateKey(SecretBytes)} with a JCA key, encoded now. */
    public PublicKeyDiscoveryBuilder recipientStaticPrivateKey(PrivateKey recipientStaticPrivateKey) {
      this.recipientStaticPrivateKey.encode(recipientStaticPrivateKey, "recipientStaticPrivateKey");
      return this;
    }

    /** @throws ValidationException if the key is missing */
    public RawEcdhKeyAgreementScheme build() {
      KeyringNames.requireSet(recipientStaticPrivateKey.key, "recipientStaticPrivateKey");
      return new Of(Kind.PUBLIC_KEY_DISCOVERY, recipientStaticPrivateKey.key.copy(), null);
    }
  }

  private static final class Of extends RawEcdhKeyAgreementScheme {

    private final Kind kind;

    Of(Kind kind, SecretBytes privateKey, byte[] recipientPublicKey) {
      super(privateKey, recipientPublicKey);
      this.kind = kind;
    }

    @Override
    public Kind kind() {
      return kind;
    }
  }
}
