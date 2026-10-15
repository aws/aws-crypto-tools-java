// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import java.security.PublicKey;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnEncryptRequest;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

/**
 * Encrypts data keys locally with the public key of an asymmetric RSA KMS key; decrypts them with KMS.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/aws-kms/aws-kms-rsa-keyring.md">AWS KMS RSA keyring</a>.
 *
 * <p>Each encrypted data key has provider id {@code aws-kms-rsa}, provider info = the UTF-8 {@link #kmsKeyId()},
 * and ciphertext = RSA-OAEP of the SHA-384 digest of the serialized encryption context followed by the key material.
 * KMS Decrypt gets no encryption context (asymmetric keys take none); the digest binds the context instead.
 * Thread-safe.
 *
 * <p>Configure the key ARN for a keyring that encrypts and decrypts. An alias ARN is accepted at creation, and the keyring
 * encrypts with the configured public key without calling KMS, but its {@link #onDecrypt} fails with a {@link ValidationException}
 * whose message starts "Alias cannot be used for Decrypt". Its encrypted data keys name the alias ARN, which a keyring configured
 * with the key ARN does not match either, so no AWS KMS RSA keyring decrypts them.
 */
public final class AwsKmsRsaKeyring implements Keyring {

  // Null when the keyring cannot encrypt.
  private final byte[] publicKey;
  private final String kmsKeyId;
  private final EncryptionAlgorithmSpec encryptionAlgorithm;
  // Null when the keyring cannot decrypt.
  private final KmsClient kmsClient;
  private final List<String> grantTokens;

  private AwsKmsRsaKeyring() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  public static Builder builder() {
    return new Builder();
  }

  /** The KMS key's public key as UTF-8 PEM (SubjectPublicKeyInfo); required to encrypt. A copy. */
  public Optional<byte[]> publicKey() {
    return publicKey == null ? Optional.empty() : Optional.of(publicKey.clone());
  }

  /** ARN of the RSA KMS key. An alias ARN builds a keyring that encrypts but cannot decrypt: see the class description. */
  public String kmsKeyId() {
    return kmsKeyId;
  }

  /** RSAES_OAEP_SHA_1 or RSAES_OAEP_SHA_256. */
  public EncryptionAlgorithmSpec encryptionAlgorithm() {
    return encryptionAlgorithm;
  }

  /** Client in the key's Region; required to decrypt. Not closed by the keyring. */
  public Optional<KmsClient> kmsClient() {
    return Optional.ofNullable(kmsClient);
  }

  /** Grant tokens sent with every KMS call. */
  public List<String> grantTokens() {
    return grantTokens;
  }

  /**
   * {@inheritDoc}
   *
   * <p>Fails without a public key, and for a suite with an asymmetric signature.
   */
  @Override
  public EncryptionMaterials onEncrypt(OnEncryptRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /**
   * {@inheritDoc}
   *
   * <p>Fails without a KMS client, when {@link #kmsKeyId()} is an alias ARN, and for a suite with an asymmetric signature.
   * Tries each {@code aws-kms-rsa} encrypted data key whose provider info is this key's ARN or, for a multi-Region key,
   * a replica's; one whose provider info is not a KMS ARN fails the whole call.
   */
  @Override
  public DecryptionMaterials onDecrypt(OnDecryptRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /**
   * Not thread-safe. At least one of {@code publicKey} (to encrypt) and {@code kmsClient} (to decrypt) is required.
   * Requires {@code kmsKeyId}, {@code encryptionAlgorithm}.
   * {@link #build()} throws {@link software.amazon.cryptography.mpl.exceptions.ValidationException} for invalid settings.
   */
  public static final class Builder {

    private byte[] publicKey;
    private String kmsKeyId;
    private EncryptionAlgorithmSpec encryptionAlgorithm;
    private KmsClient kmsClient;
    private Collection<String> grantTokens;

    private Builder() {}

    /** The KMS key's public key as UTF-8 PEM (SubjectPublicKeyInfo); required to encrypt. {@link #build()} requires a modulus of at least 2048 bits. Copied. */
    //= spec/framework/aws-kms/aws-kms-rsa-keyring.md#initialization
    //= type=implication
    //# - MAY provide a PEM encoded Public Key
    public Builder publicKey(byte[] publicKey) {
      this.publicKey = publicKey == null ? null : publicKey.clone();
      return this;
    }

    /**
     * {@link #publicKey(byte[])} with the PEM of {@code publicKey.getEncoded()}, so the keyring behaves as with those bytes.
     * For the DER that KMS {@code GetPublicKey} returns, decode it with {@code KeyFactory.getInstance("RSA")} and an
     * {@code X509EncodedKeySpec}.
     *
     * @throws ValidationException if the key has no encoding
     */
    public Builder publicKey(PublicKey publicKey) {
      throw new UnsupportedOperationException("not implemented yet");
    }

    /** ARN of the RSA KMS key. An alias ARN builds a keyring that encrypts but cannot decrypt: see the class description. */
    //= spec/framework/aws-kms/aws-kms-rsa-keyring.md#initialization
    //= type=implication
    //# - MUST provide an AWS KMS key identifier
    public Builder kmsKeyId(String kmsKeyId) {
      this.kmsKeyId = kmsKeyId;
      return this;
    }

    /** RSAES_OAEP_SHA_1 or RSAES_OAEP_SHA_256. */
    //= spec/framework/aws-kms/aws-kms-rsa-keyring.md#initialization
    //= type=implication
    //# - MUST provide an [AWS KMS Encryption Algorithm](#supported-padding-schemes)
    public Builder encryptionAlgorithm(EncryptionAlgorithmSpec encryptionAlgorithm) {
      this.encryptionAlgorithm = encryptionAlgorithm;
      return this;
    }

    /** Client in the key's Region; required to decrypt. Not closed by the keyring. */
    //= spec/framework/aws-kms/aws-kms-rsa-keyring.md#initialization
    //= type=implication
    //# - MAY provide an AWS KMS SDK client
    public Builder kmsClient(KmsClient kmsClient) {
      this.kmsClient = kmsClient;
      return this;
    }

    //= spec/framework/aws-kms/aws-kms-rsa-keyring.md#initialization
    //= type=implication
    //# - MAY provide a list of Grant Tokens
    public Builder grantTokens(Collection<String> grantTokens) {
      this.grantTokens = grantTokens;
      return this;
    }

    public AwsKmsRsaKeyring build() {
      throw new UnsupportedOperationException("not implemented yet");
    }
  }
}
