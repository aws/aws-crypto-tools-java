// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import java.util.Collection;
import java.util.List;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnEncryptRequest;

/**
 * Wraps data keys with a key derived by ECDH, where one party's key is a KMS key agreement key.
 * The wrapping and provider info are those of {@link RawEcdhKeyring}.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/aws-kms/aws-kms-ecdh-keyring.md">AWS KMS ECDH keyring</a>.
 *
 * <p>Each encrypted data key has provider id {@code aws-kms-ecdh} and names the sender's and recipient's compressed public keys
 * in its provider info. KMS DeriveSharedSecret derives the shared secret with the configured KMS key.
 * On decrypt the keyring also tries {@code raw-ecdh} keys,
 * and a static keyring accepts a key whose sender and recipient are its own recipient and sender.
 * Thread-safe.
 */
//= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#interface
//= type=implication
//# MUST implement the [AWS Encryption SDK Keyring interface](../keyring-interface.md#interface)
public final class AwsKmsEcdhKeyring implements Keyring {

  private final KmsEcdhStaticConfigurations keyAgreementScheme;
  private final EcdhCurveSpec curveSpec;
  private final KmsClient kmsClient;
  private final List<String> grantTokens;

  private AwsKmsEcdhKeyring() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Which keys are fixed: see {@link KmsEcdhStaticConfigurations}. */
  public KmsEcdhStaticConfigurations keyAgreementScheme() {
    return keyAgreementScheme;
  }

  /** The curve of both key pairs. */
  public EcdhCurveSpec curveSpec() {
    return curveSpec;
  }

  /** Client in the KMS key's Region. Not closed by the keyring. */
  public KmsClient kmsClient() {
    return kmsClient;
  }

  /** Grant tokens sent with every KMS call. */
  public List<String> grantTokens() {
    return grantTokens;
  }

//= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
//= type=implication
//# OnEncrypt MUST take [encryption materials](structures.md#encryption-materials) as input.
  @Override
  public EncryptionMaterials onEncrypt(OnEncryptRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /**
   * {@inheritDoc}
   *
   * <p>Every {@code aws-kms-ecdh} and {@code raw-ecdh} key is parsed before any is tried; a malformed provider info fails the whole call.
   */
  @Override
  public DecryptionMaterials onDecrypt(OnDecryptRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /**
   * Not thread-safe.
   * Requires {@code keyAgreementScheme}, {@code curveSpec}, {@code kmsClient}.
   * {@link #build()} calls KMS GetPublicKey unless the sender's public key is supplied, and throws
   * {@link software.amazon.cryptography.mpl.exceptions.ValidationException} for invalid settings:
   * an invalid KMS key identifier, a public key that does not parse, is not on {@code curveSpec}, or is a point with x = 0, or {@code SM2};
   * {@link software.amazon.cryptography.mpl.exceptions.ServiceException} if GetPublicKey's response does not name the requested identifier
   * (KMS names the key by ARN, so a key id or alias fails) or the key is not a key agreement key;
   * and the exception for a failed KMS call if GetPublicKey fails.
   */
  public static final class Builder {

    private KmsEcdhStaticConfigurations keyAgreementScheme;
    private EcdhCurveSpec curveSpec;
    private KmsClient kmsClient;
    private Collection<String> grantTokens;

    private Builder() {}

    /** Which keys are fixed: see {@link KmsEcdhStaticConfigurations}. */
    public Builder keyAgreementScheme(KmsEcdhStaticConfigurations keyAgreementScheme) {
      this.keyAgreementScheme = keyAgreementScheme;
      return this;
    }

    /** The curve of both key pairs. */
    public Builder curveSpec(EcdhCurveSpec curveSpec) {
      this.curveSpec = curveSpec;
      return this;
    }

    /** Client in the KMS key's Region. Not closed by the keyring. */
    public Builder kmsClient(KmsClient kmsClient) {
      this.kmsClient = kmsClient;
      return this;
    }

    public Builder grantTokens(Collection<String> grantTokens) {
      this.grantTokens = grantTokens;
      return this;
    }

    public AwsKmsEcdhKeyring build() {
      throw new UnsupportedOperationException("not implemented yet");
    }
  }
}
