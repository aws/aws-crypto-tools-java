// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import java.security.PublicKey;
import software.amazon.cryptography.mpl.internal.KeyringNames;
import software.amazon.cryptography.mpl.internal.primitives.Pem;

/**
 * Which keys an {@link AwsKmsEcdhKeyring} uses. Create one with the static methods; there are no other kinds.
 * Public keys are DER (X.509 SubjectPublicKeyInfo) and are copied.
 * The overloads that take JCA keys encode them that way, so a keyring behaves as with those bytes;
 * they throw {@link software.amazon.cryptography.mpl.exceptions.ValidationException} for a key with no encoding.
 * The static methods throw {@link software.amazon.cryptography.mpl.exceptions.ValidationException} for a null argument;
 * {@link AwsKmsEcdhKeyring.Builder#build()} checks the values themselves.
 * Immutable.
 */
public abstract class KmsEcdhStaticConfigurations {

  /** The kinds, for {@code switch}. More constants may be added; a {@code switch} needs a {@code default} branch. */
  public enum Kind {
    KMS_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY,
    KMS_PUBLIC_KEY_DISCOVERY,
  }

  // The KMS key whose private key derives the shared secret: the sender's, or for discovery the recipient's.
  private final String kmsIdentifier;
  // Null unless supplied by the caller.
  private final byte[] senderPublicKey;
  // Null for discovery.
  private final byte[] recipientPublicKey;

  private KmsEcdhStaticConfigurations(String kmsIdentifier, byte[] senderPublicKey, byte[] recipientPublicKey) {
    this.kmsIdentifier = kmsIdentifier;
    this.senderPublicKey = senderPublicKey;
    this.recipientPublicKey = recipientPublicKey;
  }

  /**
   * The sender is a KMS key agreement key; {@code recipientPublicKey} is fixed. Encrypts and decrypts.
   * The keyring fetches the sender's public key with KMS GetPublicKey when it is built.
   */
  public static KmsEcdhStaticConfigurations kmsPrivateKeyToStaticPublicKey(String senderKmsIdentifier, byte[] recipientPublicKey) {
    KeyringNames.requireSet(senderKmsIdentifier, "senderKmsIdentifier");
    KeyringNames.requireSet(recipientPublicKey, "recipientPublicKey");
    return new Of(Kind.KMS_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY, senderKmsIdentifier, null, recipientPublicKey.clone());
  }

  /** As above with the sender's public key supplied, so the keyring makes no GetPublicKey call. */
  public static KmsEcdhStaticConfigurations kmsPrivateKeyToStaticPublicKey(
    String senderKmsIdentifier,
    byte[] senderPublicKey,
    byte[] recipientPublicKey
  ) {
    KeyringNames.requireSet(senderKmsIdentifier, "senderKmsIdentifier");
    KeyringNames.requireSet(senderPublicKey, "senderPublicKey");
    KeyringNames.requireSet(recipientPublicKey, "recipientPublicKey");
    return new Of(Kind.KMS_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY, senderKmsIdentifier, senderPublicKey.clone(), recipientPublicKey.clone());
  }

  /** {@link #kmsPrivateKeyToStaticPublicKey(String, byte[])} with a JCA key. */
  public static KmsEcdhStaticConfigurations kmsPrivateKeyToStaticPublicKey(String senderKmsIdentifier, PublicKey recipientPublicKey) {
    KeyringNames.requireSet(senderKmsIdentifier, "senderKmsIdentifier");
    KeyringNames.requireSet(recipientPublicKey, "recipientPublicKey");
    return kmsPrivateKeyToStaticPublicKey(senderKmsIdentifier, Pem.encoded(recipientPublicKey, "recipientPublicKey"));
  }

  /** {@link #kmsPrivateKeyToStaticPublicKey(String, byte[], byte[])} with JCA keys. */
  public static KmsEcdhStaticConfigurations kmsPrivateKeyToStaticPublicKey(
    String senderKmsIdentifier,
    PublicKey senderPublicKey,
    PublicKey recipientPublicKey
  ) {
    KeyringNames.requireSet(senderKmsIdentifier, "senderKmsIdentifier");
    KeyringNames.requireSet(senderPublicKey, "senderPublicKey");
    KeyringNames.requireSet(recipientPublicKey, "recipientPublicKey");
    return kmsPrivateKeyToStaticPublicKey(
      senderKmsIdentifier,
      Pem.encoded(senderPublicKey, "senderPublicKey"),
      Pem.encoded(recipientPublicKey, "recipientPublicKey")
    );
  }

  /**
   * The recipient is a KMS key agreement key; decrypts any message addressed to it, encrypts nothing.
   * The keyring fetches the recipient's public key with KMS GetPublicKey when it is built.
   */
  public static KmsEcdhStaticConfigurations kmsPublicKeyDiscovery(String recipientKmsIdentifier) {
    KeyringNames.requireSet(recipientKmsIdentifier, "recipientKmsIdentifier");
    return new Of(Kind.KMS_PUBLIC_KEY_DISCOVERY, recipientKmsIdentifier, null, null);
  }

  public abstract Kind kind();

  /** The sender's KMS key, or for discovery the recipient's. */
  String kmsIdentifier() {
    return kmsIdentifier;
  }

  /** Null unless the caller supplied it. Not a copy. */
  byte[] senderPublicKey() {
    return senderPublicKey;
  }

  /** Null for discovery. Not a copy. */
  byte[] recipientPublicKey() {
    return recipientPublicKey;
  }

  private static final class Of extends KmsEcdhStaticConfigurations {

    private final Kind kind;

    Of(Kind kind, String kmsIdentifier, byte[] senderPublicKey, byte[] recipientPublicKey) {
      super(kmsIdentifier, senderPublicKey, recipientPublicKey);
      this.kind = kind;
    }

    @Override
    public Kind kind() {
      return kind;
    }
  }
}
