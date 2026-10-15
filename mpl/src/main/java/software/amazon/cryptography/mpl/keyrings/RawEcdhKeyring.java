// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnEncryptRequest;

/**
 * Wraps data keys with a key derived by ECDH from local keys.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/raw-ecdh-keyring.md">Raw ECDH keyring</a>.
 *
 * <p>Each encrypted data key has provider id {@code raw-ecdh} and names the sender's and recipient's compressed public keys
 * in its provider info. On decrypt the keyring also tries {@code aws-kms-ecdh} keys,
 * and a static keyring accepts a key whose sender and recipient are its own recipient and sender.
 * Thread-safe.
 */
//= spec/framework/raw-ecdh-keyring.md#interface
//= type=implication
//# MUST implement the [AWS Encryption SDK Keyring interface](../keyring-interface.md#interface)
public final class RawEcdhKeyring implements Keyring {

  private final RawEcdhStaticConfigurations keyAgreementScheme;
  private final EcdhCurveSpec curveSpec;
  // The configured key, or for discovery the one derived from the recipient's private key.
  private final byte[] recipientPublicKey;
  private final byte[] compressedRecipientPublicKey;
  // Empty unless the sender key pair is static.
  private final byte[] compressedSenderPublicKey;

  private RawEcdhKeyring(Builder builder, byte[] recipientPublicKey, byte[] compressedRecipientPublicKey, byte[] compressedSenderPublicKey) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Which keys are fixed: see {@link RawEcdhStaticConfigurations}. */
  public RawEcdhStaticConfigurations keyAgreementScheme() {
    return keyAgreementScheme;
  }

  /** The curve of both key pairs. */
  public EcdhCurveSpec curveSpec() {
    return curveSpec;
  }

//= spec/framework/raw-ecdh-keyring.md#onencrypt
//= type=implication
//# OnEncrypt MUST take [encryption materials](structures.md#encryption-materials) as input.
  @Override
  public EncryptionMaterials onEncrypt(OnEncryptRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  @Override
  public DecryptionMaterials onDecrypt(OnDecryptRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /**
   * Not thread-safe.
   * Requires {@code keyAgreementScheme}, {@code curveSpec}.
   * {@link #build()} throws {@link software.amazon.cryptography.mpl.exceptions.ValidationException} for invalid settings:
   * a key that does not parse, a key not on {@code curveSpec}, a recipient public key whose point has x = 0, or {@code SM2}.
   *
   * <p>On decrypt, an encrypted data key whose sender public key has x = 0 fails like any other key that does not decrypt.
   */
  public static final class Builder {

    private RawEcdhStaticConfigurations keyAgreementScheme;
    private EcdhCurveSpec curveSpec;

    private Builder() {}

    /** Which keys are fixed: see {@link RawEcdhStaticConfigurations}. */
    public Builder keyAgreementScheme(RawEcdhStaticConfigurations keyAgreementScheme) {
      this.keyAgreementScheme = keyAgreementScheme;
      return this;
    }

    /** The curve of both key pairs. */
    public Builder curveSpec(EcdhCurveSpec curveSpec) {
      this.curveSpec = curveSpec;
      return this;
    }

    public RawEcdhKeyring build() {
      throw new UnsupportedOperationException("not implemented yet");
    }
  }
}
