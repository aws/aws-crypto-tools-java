// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keyrings;

import java.security.PrivateKey;
import java.security.PublicKey;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.internal.KeyringNames;
import software.amazon.cryptography.materialproviders.internal.primitives.Pem;

/**
 * Which keys a {@link RawEcdhKeyring} holds. Create one with the static methods; there are no other kinds.
 * Private keys are UTF-8 PEM (PKCS #8); public keys are DER (X.509 SubjectPublicKeyInfo); both are copied.
 * The overloads that take JCA keys encode them that way, so a keyring behaves as with those bytes;
 * they throw {@link software.amazon.cryptography.materialproviders.exceptions.ValidationException} for a key with no encoding.
 * The static methods throw {@link software.amazon.cryptography.materialproviders.exceptions.ValidationException} for a null key;
 * {@link RawEcdhKeyring.Builder#build()} checks the keys themselves.
 * Immutable.
 */
public abstract class RawEcdhStaticConfigurations {

  /** The kinds, for {@code switch}. More constants may be added; a {@code switch} needs a {@code default} branch. */
  public enum Kind {
    RAW_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY,
    EPHEMERAL_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY,
    PUBLIC_KEY_DISCOVERY,
  }

  private final SecretBytes privateKey;
  private final byte[] recipientPublicKey;

  private RawEcdhStaticConfigurations(SecretBytes privateKey, byte[] recipientPublicKey) {
    this.privateKey = privateKey;
    this.recipientPublicKey = recipientPublicKey;
  }

  /** A fixed sender key pair and recipient public key; encrypts and decrypts. */
  public static RawEcdhStaticConfigurations rawPrivateKeyToStaticPublicKey(SecretBytes senderStaticPrivateKey, byte[] recipientPublicKey) {
    KeyringNames.requireSet(senderStaticPrivateKey, "senderStaticPrivateKey");
    KeyringNames.requireSet(recipientPublicKey, "recipientPublicKey");
    return new Of(Kind.RAW_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY, senderStaticPrivateKey.copy(), recipientPublicKey.clone());
  }

  /** {@link #rawPrivateKeyToStaticPublicKey(SecretBytes, byte[])} with JCA keys. */
  public static RawEcdhStaticConfigurations rawPrivateKeyToStaticPublicKey(PrivateKey senderStaticPrivateKey, PublicKey recipientPublicKey) {
    KeyringNames.requireSet(senderStaticPrivateKey, "senderStaticPrivateKey");
    KeyringNames.requireSet(recipientPublicKey, "recipientPublicKey");
    byte[] recipient = Pem.encoded(recipientPublicKey, "recipientPublicKey").clone();
    return new Of(Kind.RAW_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY, Pem.privateKey(senderStaticPrivateKey, "senderStaticPrivateKey"), recipient);
  }

  /** A new sender key pair per message; encrypts only. */
  public static RawEcdhStaticConfigurations ephemeralPrivateKeyToStaticPublicKey(byte[] recipientPublicKey) {
    KeyringNames.requireSet(recipientPublicKey, "recipientPublicKey");
    return new Of(Kind.EPHEMERAL_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY, null, recipientPublicKey.clone());
  }

  /** {@link #ephemeralPrivateKeyToStaticPublicKey(byte[])} with a JCA key. */
  public static RawEcdhStaticConfigurations ephemeralPrivateKeyToStaticPublicKey(PublicKey recipientPublicKey) {
    KeyringNames.requireSet(recipientPublicKey, "recipientPublicKey");
    return new Of(Kind.EPHEMERAL_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY, null, Pem.encoded(recipientPublicKey, "recipientPublicKey").clone());
  }

  /** The recipient's private key; decrypts any message addressed to it, encrypts nothing. */
  public static RawEcdhStaticConfigurations publicKeyDiscovery(SecretBytes recipientStaticPrivateKey) {
    KeyringNames.requireSet(recipientStaticPrivateKey, "recipientStaticPrivateKey");
    return new Of(Kind.PUBLIC_KEY_DISCOVERY, recipientStaticPrivateKey.copy(), null);
  }

  /** {@link #publicKeyDiscovery(SecretBytes)} with a JCA key. */
  public static RawEcdhStaticConfigurations publicKeyDiscovery(PrivateKey recipientStaticPrivateKey) {
    KeyringNames.requireSet(recipientStaticPrivateKey, "recipientStaticPrivateKey");
    return new Of(Kind.PUBLIC_KEY_DISCOVERY, Pem.privateKey(recipientStaticPrivateKey, "recipientStaticPrivateKey"), null);
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

  private static final class Of extends RawEcdhStaticConfigurations {

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
