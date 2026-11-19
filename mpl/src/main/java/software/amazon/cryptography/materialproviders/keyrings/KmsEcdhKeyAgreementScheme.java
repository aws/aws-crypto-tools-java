// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keyrings;

import java.security.PublicKey;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.internal.KeyringNames;
import software.amazon.cryptography.materialproviders.internal.primitives.Pem;

/**
 * Which keys an {@link AwsKmsEcdhKeyring} uses. Build one with the builder each static method returns; there are no other kinds.
 * Public keys are DER (X.509 SubjectPublicKeyInfo) and are copied.
 * The setters that take JCA keys encode them that way, so a keyring behaves as with those bytes;
 * they throw {@link ValidationException} for a key with no encoding.
 * {@code build()} throws {@link ValidationException} for a missing member; {@link AwsKmsEcdhKeyring.Builder#build()} checks the values themselves.
 * Immutable.
 */
public abstract class KmsEcdhKeyAgreementScheme {

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

  private KmsEcdhKeyAgreementScheme(String kmsIdentifier, byte[] senderPublicKey, byte[] recipientPublicKey) {
    this.kmsIdentifier = kmsIdentifier;
    this.senderPublicKey = senderPublicKey;
    this.recipientPublicKey = recipientPublicKey;
  }

  /**
   * The sender is a KMS key agreement key; the recipient's public key is fixed. Encrypts and decrypts.
   * Requires {@code senderKmsIdentifier} and {@code recipientPublicKey}.
   */
  public static KmsPrivateKeyToStaticPublicKeyBuilder kmsPrivateKeyToStaticPublicKey() {
    return new KmsPrivateKeyToStaticPublicKeyBuilder();
  }

  /**
   * The recipient is a KMS key agreement key; decrypts any message addressed to it, encrypts nothing.
   * Requires {@code recipientKmsIdentifier}. The keyring fetches the recipient's public key with KMS GetPublicKey when it is built.
   */
  public static KmsPublicKeyDiscoveryBuilder kmsPublicKeyDiscovery() {
    return new KmsPublicKeyDiscoveryBuilder();
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

  // Copied or encoded when set; null is a missing key.
  private static byte[] publicKey(byte[] key) {
    return key == null ? null : key.clone();
  }

  private static byte[] publicKey(PublicKey key, String name) {
    return key == null ? null : Pem.encoded(key, name).clone();
  }

  private static byte[] copy(byte[] key) {
    return key == null ? null : key.clone();
  }

  /** Not thread-safe. */
  public static final class KmsPrivateKeyToStaticPublicKeyBuilder {

    private String senderKmsIdentifier;
    private byte[] senderPublicKey;
    private byte[] recipientPublicKey;

    private KmsPrivateKeyToStaticPublicKeyBuilder() {}

    /** The sender's KMS key agreement key. */
    public KmsPrivateKeyToStaticPublicKeyBuilder senderKmsIdentifier(String senderKmsIdentifier) {
      this.senderKmsIdentifier = senderKmsIdentifier;
      return this;
    }

    /** Optional: the sender's public key, so the keyring makes no KMS GetPublicKey call when it is built. */
    public KmsPrivateKeyToStaticPublicKeyBuilder senderPublicKey(byte[] senderPublicKey) {
      this.senderPublicKey = publicKey(senderPublicKey);
      return this;
    }

    /** {@link #senderPublicKey(byte[])} with a JCA key. */
    public KmsPrivateKeyToStaticPublicKeyBuilder senderPublicKey(PublicKey senderPublicKey) {
      this.senderPublicKey = publicKey(senderPublicKey, "senderPublicKey");
      return this;
    }

    public KmsPrivateKeyToStaticPublicKeyBuilder recipientPublicKey(byte[] recipientPublicKey) {
      this.recipientPublicKey = publicKey(recipientPublicKey);
      return this;
    }

    public KmsPrivateKeyToStaticPublicKeyBuilder recipientPublicKey(PublicKey recipientPublicKey) {
      this.recipientPublicKey = publicKey(recipientPublicKey, "recipientPublicKey");
      return this;
    }

    /** @throws ValidationException if {@code senderKmsIdentifier} or {@code recipientPublicKey} is missing */
    public KmsEcdhKeyAgreementScheme build() {
      KeyringNames.requireSet(senderKmsIdentifier, "senderKmsIdentifier");
      KeyringNames.requireSet(recipientPublicKey, "recipientPublicKey");
      return new Of(Kind.KMS_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY, senderKmsIdentifier, copy(senderPublicKey), recipientPublicKey.clone());
    }
  }

  /** Not thread-safe. */
  public static final class KmsPublicKeyDiscoveryBuilder {

    private String recipientKmsIdentifier;

    private KmsPublicKeyDiscoveryBuilder() {}

    /** The recipient's KMS key agreement key. */
    public KmsPublicKeyDiscoveryBuilder recipientKmsIdentifier(String recipientKmsIdentifier) {
      this.recipientKmsIdentifier = recipientKmsIdentifier;
      return this;
    }

    /** @throws ValidationException if {@code recipientKmsIdentifier} is missing */
    public KmsEcdhKeyAgreementScheme build() {
      KeyringNames.requireSet(recipientKmsIdentifier, "recipientKmsIdentifier");
      return new Of(Kind.KMS_PUBLIC_KEY_DISCOVERY, recipientKmsIdentifier, null, null);
    }
  }

  private static final class Of extends KmsEcdhKeyAgreementScheme {

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
