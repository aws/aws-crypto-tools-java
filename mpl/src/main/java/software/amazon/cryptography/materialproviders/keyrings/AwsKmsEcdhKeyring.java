// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keyrings;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DeriveSharedSecretRequest;
import software.amazon.awssdk.services.kms.model.DeriveSharedSecretResponse;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.KeyAgreementAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnDecryptResponse;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;
import software.amazon.cryptography.materialproviders.exceptions.ServiceException;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.internal.AwsErrors;
import software.amazon.cryptography.materialproviders.internal.AwsArnParsing.AwsKmsIdentifier;
import software.amazon.cryptography.materialproviders.internal.EcdhEdkWrapping;
import software.amazon.cryptography.materialproviders.internal.EdkWrapping;
import software.amazon.cryptography.materialproviders.internal.KeyringNames;
import software.amazon.cryptography.materialproviders.internal.KmsDataKeys;
import software.amazon.cryptography.materialproviders.internal.primitives.Bytes;
import software.amazon.cryptography.materialproviders.internal.primitives.Ecdh;

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

  // KMS PublicKeyType: 1 to 8192 bytes.
  private static final int MAX_PUBLIC_KEY_LENGTH = 8192;

  private final KmsEcdhKeyAgreementScheme keyAgreementScheme;
  private final EcdhCurveSpec curveSpec;
  private final KmsClient kmsClient;
  private final List<String> grantTokens;
  // The configured key, or for discovery the one KMS returned for the recipient's KMS key.
  private final byte[] recipientPublicKey;
  private final byte[] compressedRecipientPublicKey;
  // Empty for discovery.
  private final byte[] compressedSenderPublicKey;

  private AwsKmsEcdhKeyring(
    Builder builder,
    List<String> grantTokens,
    byte[] recipientPublicKey,
    byte[] compressedRecipientPublicKey,
    byte[] compressedSenderPublicKey
  ) {
    this.keyAgreementScheme = builder.keyAgreementScheme;
    this.curveSpec = builder.curveSpec;
    this.kmsClient = builder.kmsClient;
    this.grantTokens = grantTokens;
    this.recipientPublicKey = recipientPublicKey;
    this.compressedRecipientPublicKey = compressedRecipientPublicKey;
    this.compressedSenderPublicKey = compressedSenderPublicKey;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Which keys are fixed: see {@link KmsEcdhKeyAgreementScheme}. */
  public KmsEcdhKeyAgreementScheme keyAgreementScheme() {
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
  public OnEncryptResponse onEncrypt(OnEncryptRequest request) {
    EncryptionMaterials materials = request.materials();
    //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
    //= type=implication
    //# OnEncrypt MUST fail if configured with a
    //# [KmsPublicKeyDiscovery Key Agreement Configuration](../key-agreement-schemas.md#kmspublickeydiscovery)
    if (isDiscovery()) {
      throw new ValidationException("KmsPublicKeyDiscovery Key Agreement Scheme is forbidden on encrypt.");
    }
    //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
    //# If the call to KMS DeriveSharedSecret fails, the keyring MUST fail.
    byte[] sharedSecret = deriveSharedSecret(keyAgreementScheme.kmsIdentifier(), recipientPublicKey);
    try {
      //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
      //= type=implication
      //# If the keyring cannot serialize
      //# the encryption context, OnEncrypt MUST fail.
      byte[] fixedInfo = EcdhEdkWrapping.fixedInfo(curveSpec, compressedSenderPublicKey, compressedRecipientPublicKey, materials.encryptionContext());
      //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
      //# The keyring MUST perform data key wrapping according to the [Data Key Wrapping section](../raw-ecdh-keyring.md#data-key-wrapping).
      EdkWrapping.WrapResult<Void> result = EdkWrapping.wrap(
        materials,
        EcdhEdkWrapping.wrap(sharedSecret, fixedInfo),
        EcdhEdkWrapping.generateAndWrap(sharedSecret, fixedInfo)
      );
      byte[] providerInfo = EcdhEdkWrapping.providerInfo(compressedSenderPublicKey, compressedRecipientPublicKey);
      //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
      //# OnEncrypt MUST append a new [encrypted data key](../structures.md#encrypted-data-key)
      //# to the encrypted data key list in the [encryption materials](../structures.md#encryption-materials)

      //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
      //# - The [key provider id](../structures.md#key-provider-id) MUST be the UTF8 encoded string "aws-kms-ecdh".

      //= spec/framework/raw-ecdh-keyring.md#data-key-wrapping
      //# If the keyring successfully wraps the plaintext data key it MUST set it on the [encryption materials](structures.md#encryption-materials).
      return OnEncryptResponse.builder()
        .materials(result.addTo(materials, EncryptedDataKey.of(EcdhEdkWrapping.KMS_PROVIDER_ID, providerInfo, result.wrappedMaterial)))
        .build();
    } finally {
      Bytes.zero(sharedSecret);
    }
  }

  /**
   * {@inheritDoc}
   *
   * <p>Every {@code aws-kms-ecdh} and {@code raw-ecdh} key is parsed before any is tried; a malformed provider info fails the whole call.
   */
  @Override
  public OnDecryptResponse onDecrypt(OnDecryptRequest request) {
    //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
    //= type=implication
    //# OnDecrypt MUST take [decryption materials]
    //# (../structures.md#decryption-materials) and a list of [encrypted data
    //# keys](../structures.md#encrypted-data-key) as input.
    DecryptionMaterials materials = request.materials();
    List<EncryptedDataKey> encryptedDataKeys = request.encryptedDataKeys();
    //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#ondecrypt
    //# If the decryption materials already contain a plaintext data key,
    //# OnDecrypt MUST fail
    //# and MUST NOT modify the [decryption materials](structures.md#decryption-materials).
    KmsDataKeys.requireNoPlaintextDataKey(materials);
    //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#ondecrypt
    //# The set of encrypted data keys MUST first be filtered to match this keyring’s configuration.
    //# For the encrypted data key to match:
    List<Candidate> candidates = new ArrayList<>();
    for (EncryptedDataKey edk : encryptedDataKeys) {
      String id = edk.keyProviderId();
      //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#ondecrypt
      //# - The key provider ID of the encrypted data key MUST have a value equal to the UTF8 encoded strings `raw-ecdh` OR `aws-kms-ecdh`.
      if (id.equals(EcdhEdkWrapping.RAW_PROVIDER_ID) || id.equals(EcdhEdkWrapping.KMS_PROVIDER_ID)) {
        //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#ondecrypt
        //# - The [ciphertext](#ciphertext) and [key provider information](#key-provider-information) MUST be successfully deserialized.
        EcdhEdkWrapping.ProviderInfo info = EcdhEdkWrapping.parseProviderInfo(edk.keyProviderInfo());
        if (matches(info)) {
          candidates.add(new Candidate(edk, info));
        }
      }
    }
    //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#ondecrypt
    //# For each encrypted data key in the filtered set, one at a time, the OnDecrypt MUST attempt to decrypt the data key.
    //# If this attempt results in an error, then these errors MUST be collected.

    //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#ondecrypt
    //# If OnDecrypt fails to successfully decrypt any encrypted data key,
    //# then it MUST yield an error that includes all the collected errors.
    return OnDecryptResponse.builder()
      .materials(KmsDataKeys.firstSuccess(candidates, candidate -> decrypt(materials, candidate), encryptedDataKeys, materials.algorithmSuite()))
      .build();
  }

  private boolean isDiscovery() {
    return keyAgreementScheme.kind() == KmsEcdhKeyAgreementScheme.Kind.KMS_PUBLIC_KEY_DISCOVERY;
  }

  // Discovery checks only the recipient; a static keyring also accepts its own keys with the roles swapped.
  private boolean matches(EcdhEdkWrapping.ProviderInfo info) {
    boolean recipient = Arrays.equals(compressedRecipientPublicKey, info.recipientPublicKey);
    //= spec/framework/key-agreement-schemas.md#kmspublickeydiscovery
    //# - MUST verify that the configured recipient's public key
    //#   matches the public key stored on the message ciphertext.
    if (isDiscovery()) {
      return recipient;
    }
    //= spec/framework/key-agreement-schemas.md#kmsprivatekeytostaticpublickey
    //# - MUST verify that both the configured sender's and recipient's
    //#   public keys match the public keys stored on the message ciphertext.
    return (
      (recipient && Arrays.equals(compressedSenderPublicKey, info.senderPublicKey)) ||
      (Arrays.equals(compressedSenderPublicKey, info.recipientPublicKey) && Arrays.equals(compressedRecipientPublicKey, info.senderPublicKey))
    );
  }

  private DecryptionMaterials decrypt(DecryptionMaterials materials, Candidate candidate) {
    byte[] ciphertext = candidate.edk.ciphertext();
    EdkWrapping.providerWrappedMaterial(ciphertext, materials.algorithmSuite());
    // The other party's key. A static keyring's matching key names its configured recipient either as the recipient
    // (this keyring sent it) or as the sender (sent to this keyring), so the other key is always the configured recipient's.
    // It goes to KMS in the standard encoding (named curve, uncompressed point), as decompressed from the message.
    // A discovery keyring takes the message's sender key.
    byte[] otherPublicKey;
    if (isDiscovery()) {
      otherPublicKey = Ecdh.decompressPublicKey(candidate.info.senderPublicKey, curveSpec);
      EcdhEdkWrapping.requireValidPublicKey(Ecdh.validatePublicKey(curveSpec, otherPublicKey), "sender public key in the provider info");
    } else {
      //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#ondecrypt
      //= type=exception
      //= reason=A static keyring sends KMS the recipient key decompressed from its compressed form (named curve, uncompressed point), so a recipient key configured in another valid encoding still decrypts.
      //# - `PublicKey` MUST be the configured Recipient Public Key on the schema
      otherPublicKey = Ecdh.decompressPublicKey(compressedRecipientPublicKey, curveSpec);
    }
    //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#ondecrypt
    //# The keyring MUST derive the shared secret
    //# by calling [AWS KMS DeriveSharedSecret]()
    byte[] sharedSecret = deriveSharedSecret(keyAgreementScheme.kmsIdentifier(), otherPublicKey);
    try {
      EdkWrapping.UnwrapResult<Void> unwrapped = EdkWrapping.unwrap(ciphertext, materials, EcdhEdkWrapping.unwrap(sharedSecret, curveSpec, candidate.info));
      //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#ondecrypt
      //# - MUST set the plaintext data key on the [decryption materials](./structures.md#decryption-materials)
      //# - MUST immediately return the modified [decryption materials](../structures.md#decryption-materials).
      return unwrapped.addTo(materials);
    } finally {
      Bytes.zero(sharedSecret);
    }
  }

  // DeriveSharedSecret: the response must name the requested key and the ECDH algorithm.
  //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
  //= type=implication
  //# To attempt to generate a shared secret,
  //# OnEncrypt MUST call [AWS KMS DeriveSharedSecret]()
  //# the keyring MUST call with a request constructed as follows:
  private byte[] deriveSharedSecret(String kmsIdentifier, byte[] publicKey) {
    DeriveSharedSecretRequest request = DeriveSharedSecretRequest
      .builder()
      //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
      //= type=implication
      //# - `KeyId` MUST be the configured AWS KMS key identifier in the schema
      .keyId(kmsIdentifier)
      //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
      //= type=implication
      //# - `KeyAgreementAlgorithm` MUST be "ECDH"
      .keyAgreementAlgorithm(KeyAgreementAlgorithmSpec.ECDH)
      //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
      //= type=implication
      //# - `PublicKey` MUST be the configured Recipient Public Key on the schema
      .publicKey(SdkBytes.fromByteArray(publicKey))
      //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
      //= type=implication
      //# - `GrantTokens` MUST be this keyring's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
      .grantTokens(grantTokens)
      .build();
    DeriveSharedSecretResponse response;
    try {
      response = kmsClient.deriveSharedSecret(request);
    } catch (SdkException e) {
      //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
      //= type=implication
      //# If the call to KMS DeriveSharedSecret fails, the keyring MUST fail.
      throw AwsErrors.from(e);
    }
    boolean valid =
      response.sharedSecret() != null &&
      kmsIdentifier.equals(response.keyId()) &&
      response.keyAgreementAlgorithm() == KeyAgreementAlgorithmSpec.ECDH;
    if (!valid) {
      throw new ServiceException("Invalid response from KMS DeriveSharedSecret");
    }
    return response.sharedSecret().asByteArray();
  }

  private static boolean isValidKmsPublicKey(byte[] publicKey) {
    return publicKey.length >= 1 && publicKey.length <= MAX_PUBLIC_KEY_LENGTH;
  }

  private static final class Candidate {

    final EncryptedDataKey edk;
    final EcdhEdkWrapping.ProviderInfo info;

    Candidate(EncryptedDataKey edk, EcdhEdkWrapping.ProviderInfo info) {
      this.edk = edk;
      this.info = info;
    }
  }

  /**
   * Not thread-safe.
   * Requires {@code keyAgreementScheme}, {@code curveSpec}, {@code kmsClient}.
   * {@link #build()} calls KMS GetPublicKey unless the sender's public key is supplied, and throws
   * {@link software.amazon.cryptography.materialproviders.exceptions.ValidationException} for invalid settings:
   * an invalid KMS key identifier, a public key that does not parse, is not on {@code curveSpec}, or is a point with x = 0, or {@code SM2};
   * {@link software.amazon.cryptography.materialproviders.exceptions.ServiceException} if GetPublicKey's response does not name the requested identifier
   * (KMS names the key by ARN, so a key id or alias fails) or the key is not a key agreement key;
   * and the exception for a failed KMS call if GetPublicKey fails.
   */
  public static final class Builder {

    private KmsEcdhKeyAgreementScheme keyAgreementScheme;
    private EcdhCurveSpec curveSpec;
    private KmsClient kmsClient;
    private Collection<String> grantTokens;

    private Builder() {}

    /** Which keys are fixed: see {@link KmsEcdhKeyAgreementScheme}. */
    public Builder keyAgreementScheme(KmsEcdhKeyAgreementScheme keyAgreementScheme) {
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

    /** Copied; a null collection is the same as an empty one. */
    public Builder grantTokens(Collection<String> grantTokens) {
      this.grantTokens = grantTokens == null ? null : new ArrayList<>(grantTokens);
      return this;
    }

    /** The same as {@link #grantTokens(Collection)} with these values; a null array is passed on as a null collection. */
    public Builder grantTokens(String... grantTokens) {
      return grantTokens(grantTokens == null ? null : Arrays.asList(grantTokens));
    }

    // CreateAwsKmsEcdhKeyring.
    public AwsKmsEcdhKeyring build() {
      //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#initialization
      //= type=implication
      //# - MUST provide a [Key Agreement Schema](#key-agreement-schema)
      KeyringNames.requireSet(keyAgreementScheme, "keyAgreementScheme");
      //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#initialization
      //= type=implication
      //# - MUST provide a [Curve Specification](#curve-specification)
      KeyringNames.requireSet(curveSpec, "curveSpec");
      //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#initialization
      //= type=implication
      //# - MUST provide an AWS KMS SDK client
      KeyringNames.requireSet(kmsClient, "kmsClient");
      //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#initialization
      //= type=implication
      //# - MAY provide a list of Grant Tokens
      List<String> tokens = KmsDataKeys.grantTokens(grantTokens);
      String kmsIdentifier = keyAgreementScheme.kmsIdentifier();
      byte[] recipientPublicKey;
      byte[] senderPublicKey = null;
      byte[] compressedSenderPublicKey = new byte[0];
      if (keyAgreementScheme.kind() == KmsEcdhKeyAgreementScheme.Kind.KMS_PUBLIC_KEY_DISCOVERY) {
        //= spec/framework/key-agreement-schemas.md#kmspublickeydiscovery
        //# - MUST provide the recipient's AWS KMS key identifier
        AwsKmsIdentifier.validateKeyId(kmsIdentifier);
        //= spec/framework/key-agreement-schemas.md#kmspublickeydiscovery
        //# the keyring MUST call
        //# `kms:GetPublicKey` on the recipient's configured KMS key ID.

        //= spec/framework/key-agreement-schemas.md#kmspublickeydiscovery
        //# If the keyring fails to retrieve the public key, the keyring MUST fail.
        recipientPublicKey = getPublicKey(kmsClient, kmsIdentifier);
      } else {
        senderPublicKey = keyAgreementScheme.senderPublicKey();
        //= spec/framework/key-agreement-schemas.md#kmsprivatekeytostaticpublickey
        //# - MAY provide the sender's public key
        //#   - Public key MUST be DER-encoded [X.509 SubjectPublicKeyInfo](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1)
        if (senderPublicKey != null) {
          if (!isValidKmsPublicKey(senderPublicKey)) {
            throw new ValidationException("Invalid SenderPublicKey length.");
          }
        } else {
          AwsKmsIdentifier.validateKeyId(kmsIdentifier);
          //= spec/framework/key-agreement-schemas.md#kmsprivatekeytostaticpublickey
          //# On initialization, if the keyring is not configured with
          //# a sender public key, the keyring MUST call
          //# `kms:GetPublicKey` on the sender's configured KMS key ID.

          //= spec/framework/key-agreement-schemas.md#kmsprivatekeytostaticpublickey
          //# If the keyring fails to retrieve the public key, the keyring MUST fail.
          senderPublicKey = getPublicKey(kmsClient, kmsIdentifier);
        }
        compressedSenderPublicKey = Ecdh.compressPublicKey(senderPublicKey);
        recipientPublicKey = keyAgreementScheme.recipientPublicKey();
        if (!isValidKmsPublicKey(recipientPublicKey)) {
          throw new ValidationException("Invalid RecipientPublicKey length.");
        }
      }
      // Throws for a key not on curveSpec. False results are rejected after the other checks, which a key may also fail.
      boolean recipientValid = Ecdh.validatePublicKey(curveSpec, recipientPublicKey);
      byte[] compressedRecipientPublicKey = Ecdh.compressPublicKey(recipientPublicKey);
      boolean senderValid = true;
      if (senderPublicKey != null) {
        // The identifier is checked again for a fetched key, as the Dafny-based MPL does; it only fails for a supplied one.
        AwsKmsIdentifier.validateKeyId(kmsIdentifier);
        senderValid = Ecdh.validatePublicKey(curveSpec, senderPublicKey);
      }
      EcdhEdkWrapping.requireValidPublicKey(recipientValid, "recipient public key");
      EcdhEdkWrapping.requireValidPublicKey(senderValid, "sender public key");
      //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#initialization
      //= type=implication
      //# the keyring MUST set the recipient's public key on the keyring.
      return new AwsKmsEcdhKeyring(this, tokens, recipientPublicKey, compressedRecipientPublicKey, compressedSenderPublicKey);
    }

    // GetEcdhPublicKey: no grant tokens; the response must name the requested key as a key agreement key.
    private static byte[] getPublicKey(KmsClient kmsClient, String kmsIdentifier) {
      GetPublicKeyResponse response;
      try {
        response = kmsClient.getPublicKey(GetPublicKeyRequest.builder().keyId(kmsIdentifier).build());
      } catch (SdkException e) {
        throw AwsErrors.from(e);
      }
      boolean valid =
        kmsIdentifier.equals(response.keyId()) &&
        response.keyUsage() == KeyUsageType.KEY_AGREEMENT &&
        response.publicKey() != null;
      if (!valid) {
        throw new ServiceException("Invalid response from KMS GetPublicKey");
      }
      return response.publicKey().asByteArray();
    }
  }
}
