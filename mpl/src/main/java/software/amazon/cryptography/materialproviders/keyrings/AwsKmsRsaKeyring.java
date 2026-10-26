// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keyrings;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnDecryptResponse;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;
import software.amazon.cryptography.materialproviders.exceptions.EncryptionContextMismatchException;
import software.amazon.cryptography.materialproviders.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.materialproviders.exceptions.ServiceException;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.internal.AwsErrors;
import software.amazon.cryptography.materialproviders.internal.AwsArnParsing.AwsKmsIdentifier;
import software.amazon.cryptography.materialproviders.internal.CanonicalEncryptionContext;
import software.amazon.cryptography.materialproviders.internal.EdkWrapping;
import software.amazon.cryptography.materialproviders.internal.KeyringNames;
import software.amazon.cryptography.materialproviders.internal.KmsDataKeys;
import software.amazon.cryptography.materialproviders.internal.Utf8;
import software.amazon.cryptography.materialproviders.internal.primitives.Bytes;
import software.amazon.cryptography.materialproviders.internal.primitives.DigestAlgorithm;
import software.amazon.cryptography.materialproviders.internal.primitives.Digests;
import software.amazon.cryptography.materialproviders.internal.primitives.Pem;
import software.amazon.cryptography.materialproviders.internal.primitives.Randoms;
import software.amazon.cryptography.materialproviders.internal.primitives.Rsa;

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

  private static final String PROVIDER_ID = "aws-kms-rsa";
  private static final int MIN_MODULUS_BITS = 2048;
  private static final int MAX_KEY_ID_LENGTH = 2048;
  private static final int MAX_CIPHERTEXT_LENGTH = 6144;
  private static final String DIGEST_MISMATCH = "Encryption context digest does not match expected value.";
  private static final String SIGNING_SUITE =
    "AwsKmsRsaKeyring cannot be used with an Algorithm Suite with asymmetric signing." +
    " Please specify an algorithm suite without asymmetric signing.";

  // Null when the keyring cannot encrypt.
  private final byte[] publicKey;
  private final String kmsKeyId;
  private final AwsKmsIdentifier identifier;
  private final EncryptionAlgorithmSpec encryptionAlgorithm;
  // Null when the keyring cannot decrypt.
  private final KmsClient kmsClient;
  private final List<String> grantTokens;

  private AwsKmsRsaKeyring(Builder builder, AwsKmsIdentifier identifier, List<String> grantTokens) {
    this.publicKey = builder.publicKey;
    this.kmsKeyId = builder.kmsKeyId;
    this.identifier = identifier;
    this.encryptionAlgorithm = builder.encryptionAlgorithm;
    this.kmsClient = builder.kmsClient;
    this.grantTokens = grantTokens;
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
  public OnEncryptResponse onEncrypt(OnEncryptRequest request) {
    EncryptionMaterials materials = request.materials();
    if (publicKey == null) {
      throw new ValidationException("A AwsKmsRsaKeyring without a public key cannot provide OnEncrypt");
    }
    //= spec/framework/aws-kms/aws-kms-rsa-keyring.md#onencrypt
    //= type=implication
    //# OnEncrypt MUST fail if the input [encryption materials](../structures.md#encryption-materials)
    //# contains an [algorithm suite](../algorithm-suites.md) containing an
    //# [asymmetric signature](../algorithm-suites.md#asymmetric-signature-algorithm).
    if (materials.algorithmSuite().isSigning()) {
      throw new ValidationException(SIGNING_SUITE);
    }
    EdkWrapping.WrapResult<Void> result = EdkWrapping.wrap(
      materials,
      (plaintextMaterial, suite, encryptionContext) -> new EdkWrapping.Wrapped<>(wrap(plaintextMaterial, encryptionContext), null),
      (suite, encryptionContext) -> {
        byte[] plaintextMaterial = Randoms.generate(suite.dataKeyLength());
        try {
          return new EdkWrapping.Generated<>(plaintextMaterial, wrap(plaintextMaterial, encryptionContext), null);
        } catch (RuntimeException e) {
          Bytes.zero(plaintextMaterial);
          throw e;
        }
      }
    );
    return OnEncryptResponse.builder()
      .materials(result.addTo(materials, EncryptedDataKey.of(PROVIDER_ID, Utf8.encode(kmsKeyId), result.wrappedMaterial)))
      .build();
  }

  /**
   * {@inheritDoc}
   *
   * <p>Fails without a KMS client, when {@link #kmsKeyId()} is an alias ARN, and for a suite with an asymmetric signature.
   * Tries each {@code aws-kms-rsa} encrypted data key whose provider info is this key's ARN or, for a multi-Region key,
   * a replica's; one whose provider info is not a KMS ARN fails the whole call.
   */
  @Override
  public OnDecryptResponse onDecrypt(OnDecryptRequest request) {
    DecryptionMaterials materials = request.materials();
    List<EncryptedDataKey> encryptedDataKeys = request.encryptedDataKeys();
    if (kmsClient == null) {
      throw new ValidationException("An AwsKmsRsaKeyring without an AWS KMS client cannot provide OnDecrypt");
    }
    KmsDataKeys.requireNoPlaintextDataKey(materials);
    KmsDataKeys.requireKeyArn(identifier, kmsKeyId);
    AlgorithmSuite suite = materials.algorithmSuite();
    //= spec/framework/aws-kms/aws-kms-rsa-keyring.md#ondecrypt
    //= type=implication
    //# OnDecrypt MUST fail if the input [decryption materials](../structures.md#decryption-materials)
    //# contains an [algorithm suite](../algorithm-suites.md) containing an
    //# [asymmetric signature](../algorithm-suites.md#asymmetric-signature-algorithm).
    if (suite.isSigning()) {
      throw new ValidationException(SIGNING_SUITE);
    }
    List<EncryptedDataKey> candidates = new ArrayList<>();
    for (EncryptedDataKey edk : encryptedDataKeys) {
      if (edk.keyProviderId().equals(PROVIDER_ID) && identifier.mrkMatches(KmsDataKeys.providerInfoArn(edk))) {
        candidates.add(edk);
      }
    }
    // The digest is computed once, after the keys are filtered: a context that cannot be serialized fails the whole call.
    if (candidates.isEmpty()) {
      throw new NoMatchingDataKeyException(KeyringNames.incorrectDataKeys(encryptedDataKeys, suite), Collections.emptyList());
    }
    byte[] digest = encryptionContextDigest(materials.encryptionContext());
    DecryptionMaterials decrypted = KmsDataKeys.firstSuccess(
      candidates,
      edk -> {
        EdkWrapping.UnwrapResult<Void> unwrapped = EdkWrapping.unwrap(
          edk.ciphertext(),
          materials,
          (wrapped, unwrapSuite, encryptionContext) -> new EdkWrapping.Unwrapped<>(unwrap(wrapped, unwrapSuite, digest), null)
        );
        return unwrapped.addTo(materials);
      },
      encryptedDataKeys,
      suite
    );
    return OnDecryptResponse.builder().materials(decrypted).build();
  }

  // KmsRsaWrapKeyMaterial: RSA-OAEP of digest || key material.
  private byte[] wrap(byte[] plaintextMaterial, EncryptionContext encryptionContext) {
    //= spec/framework/aws-kms/aws-kms-rsa-keyring.md#onencrypt
    //# OnEncrypt MUST calculate a Encryption Context Digest by:
    byte[] digest = encryptionContextDigest(encryptionContext);
    byte[] plaintext = Arrays.copyOf(digest, digest.length + plaintextMaterial.length);
    System.arraycopy(plaintextMaterial, 0, plaintext, digest.length, plaintextMaterial.length);
    try {
      return Rsa.encrypt(padding(encryptionAlgorithm), publicKey, plaintext);
    } finally {
      Bytes.zero(plaintext);
    }
  }

  // KmsRsaUnwrapKeyMaterial: KMS Decrypt, then the digest prefix is checked and removed.
  private byte[] unwrap(byte[] wrapped, AlgorithmSuite suite, byte[] digest) {
    if (wrapped.length < 1 || wrapped.length > MAX_CIPHERTEXT_LENGTH) {
      throw new ValidationException("Ciphertext length invalid");
    }
    DecryptRequest request = DecryptRequest
      .builder()
      .keyId(kmsKeyId)
      .ciphertextBlob(SdkBytes.fromByteArray(wrapped))
      .grantTokens(grantTokens)
      .encryptionAlgorithm(encryptionAlgorithm)
      .build();
    DecryptResponse response;
    try {
      response = kmsClient.decrypt(request);
    } catch (SdkException e) {
      throw AwsErrors.from(e);
    }
    if (!kmsKeyId.equals(response.keyId()) || response.plaintext() == null) {
      throw new ServiceException("Invalid response from KMS Decrypt");
    }
    byte[] plaintext = response.plaintext().asByteArray();
    try {
      // One message for both, as in the Dafny-based MPL; a wrong length is a malformed response, a wrong digest a different context.
      if (plaintext.length != digest.length + suite.dataKeyLength()) {
        throw new ServiceException(DIGEST_MISMATCH);
      }
      if (!MessageDigest.isEqual(Arrays.copyOf(plaintext, digest.length), digest)) {
        throw new EncryptionContextMismatchException(DIGEST_MISMATCH);
      }
      return Arrays.copyOfRange(plaintext, digest.length, plaintext.length);
    } finally {
      Bytes.zero(plaintext);
    }
  }

  // EncryptionContextDigest: SHA-384 of the serialized context, not truncated.
  private static byte[] encryptionContextDigest(EncryptionContext encryptionContext) {
    return Digests.digest(DigestAlgorithm.SHA_384, CanonicalEncryptionContext.serialize(encryptionContext));
  }

  // The KMS algorithm names the OAEP hash; MGF1 uses the same hash.
  private static PaddingScheme padding(EncryptionAlgorithmSpec encryptionAlgorithm) {
    return encryptionAlgorithm == EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1 ? PaddingScheme.OAEP_SHA1_MGF1 : PaddingScheme.OAEP_SHA256_MGF1;
  }

  /**
   * Not thread-safe. At least one of {@code publicKey} (to encrypt) and {@code kmsClient} (to decrypt) is required.
   * Requires {@code kmsKeyId}, {@code encryptionAlgorithm}.
   * {@link #build()} throws {@link software.amazon.cryptography.materialproviders.exceptions.ValidationException} for invalid settings.
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
      this.publicKey = publicKey == null ? null : Pem.publicKey(publicKey, "publicKey");
      return this;
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
    /** Copied; a null collection is the same as an empty one. */
    public Builder grantTokens(Collection<String> grantTokens) {
      this.grantTokens = grantTokens == null ? null : new ArrayList<>(grantTokens);
      return this;
    }

    /** The same as {@link #grantTokens(Collection)} with these values; a null array is passed on as a null collection. */
    public Builder grantTokens(String... grantTokens) {
      return grantTokens(grantTokens == null ? null : Arrays.asList(grantTokens));
    }

    // CreateAwsKmsRsaKeyring.
    public AwsKmsRsaKeyring build() {
      KeyringNames.requireSet(kmsKeyId, "kmsKeyId");
      KeyringNames.requireSet(encryptionAlgorithm, "encryptionAlgorithm");
      if (publicKey == null && kmsClient == null) {
        throw new ValidationException("A publicKey or a kmsClient is required");
      }
      if (encryptionAlgorithm != EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1 && encryptionAlgorithm != EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256) {
        throw new ValidationException("Unsupported EncryptionAlgorithmSpec");
      }
      //= spec/framework/aws-kms/aws-kms-rsa-keyring.md#initialization
      //= type=implication
      //# The AWS KMS key identifier MUST NOT be null or empty.
      //= spec/framework/aws-kms/aws-kms-rsa-keyring.md#initialization
      //= type=implication
      //# The AWS KMS key identifier MUST be [a valid identifier](../../framework/aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-identifier).
      //= spec/framework/aws-kms/aws-kms-rsa-keyring.md#initialization
      //= type=exception
      //= reason=An alias ARN is accepted at creation so the keyring can encrypt with its public key; onDecrypt rejects the alias.
      //# The AWS KMS key identifier MUST NOT be an AWS KMS alias.
      // An alias ARN passes this check: encryption needs only the public key; onDecrypt rejects the alias.
      if (kmsKeyId.isEmpty() || kmsKeyId.length() > MAX_KEY_ID_LENGTH || !isArn(kmsKeyId)) {
        throw new ValidationException("Kms Key ID must be a KMS Key ARN");
      }
      //= spec/framework/aws-kms/aws-kms-rsa-keyring.md#initialization
      //= type=implication
      //# If provided the Public Key
      //# MUST have an RSA modulus bit length greater than or equal to 2048.
      if (publicKey != null && Rsa.modulusLengthBits(publicKey) < MIN_MODULUS_BITS) {
        throw new ValidationException("Invalid public key length");
      }
      AwsKmsIdentifier identifier = AwsKmsIdentifier.validateKeyId(kmsKeyId);
      return new AwsKmsRsaKeyring(this, identifier, KmsDataKeys.grantTokens(grantTokens));
    }

    private static boolean isArn(String kmsKeyId) {
      try {
        AwsKmsIdentifier.parseArn(kmsKeyId);
        return true;
      } catch (ValidationException e) {
        return false;
      }
    }
  }
}
