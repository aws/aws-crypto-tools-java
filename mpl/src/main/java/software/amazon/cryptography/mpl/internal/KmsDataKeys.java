// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.cryptography.mpl.AlgorithmSuite;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptedDataKey;
import software.amazon.cryptography.mpl.EncryptionContext;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.mpl.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.mpl.exceptions.ServiceException;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.AwsArnParsing.AwsKmsIdentifier;
import software.amazon.cryptography.mpl.internal.primitives.Bytes;

/**
 * The KMS calls and checks shared by the symmetric KMS keyrings, per AwsKmsKeyring.dfy and AwsKmsUtils.dfy.
 *
 * <p>Each encrypted data key has provider id {@code aws-kms}, provider info = the UTF-8 key ARN KMS returned,
 * and ciphertext = the KMS ciphertext blob (after the encrypted data key, for intermediate-wrapping suites).
 * Every request carries the materials' encryption context and the grant tokens, even when empty.
 */
public final class KmsDataKeys {

  public static final String PROVIDER_ID = "aws-kms";

  private static final int MAX_GRANT_TOKENS = 10;
  private static final int MAX_GRANT_TOKEN_LENGTH = 8192;
  private static final int MAX_CIPHERTEXT_LENGTH = 6144;
  private static final int UINT16_LIMIT = 65536;
  private static final String ALL_FAILED =
    "No Configured KMS Key was able to decrypt the Data Key. The list of encountered Exceptions is available via `list`.";

  private KmsDataKeys() {}

  /** An encrypted data key a discovery keyring will ask KMS to decrypt, and the key ARN it names in the request. */
  public static final class Candidate {

    final EncryptedDataKey edk;
    final String keyId;

    public Candidate(EncryptedDataKey edk, String keyId) {
      this.edk = edk;
      this.keyId = keyId;
    }
  }

  /** One attempt to decrypt a candidate encrypted data key. */
  public interface Attempt<T> {
    DecryptionMaterials decrypt(T candidate);
  }

  /** GetValidGrantTokens: at most 10 tokens of 1 to 8192 characters; absent means none. Copied. */
  public static List<String> grantTokens(Collection<String> grantTokens) {
    if (grantTokens == null) {
      return Collections.emptyList();
    }
    List<String> tokens = new ArrayList<>(grantTokens);
    tokens.forEach(Objects::requireNonNull);
    if (tokens.size() > MAX_GRANT_TOKENS) {
      throw new ValidationException("Grant token list can have no more than 10 tokens");
    }
    for (String token : tokens) {
      if (token.isEmpty() || token.length() > MAX_GRANT_TOKEN_LENGTH) {
        throw new ValidationException("Grant token list contains a grant token with invalid length");
      }
    }
    return Collections.unmodifiableList(tokens);
  }

  /** OnEncrypt of the AWS KMS and AWS KMS MRK keyrings: GenerateDataKey without a data key, otherwise Encrypt. */
  public static EncryptionMaterials onEncrypt(KmsClient client, String keyId, List<String> grantTokens, EncryptionMaterials materials) {
    EdkWrapping.WrapResult<String> result = EdkWrapping.wrap(
      materials,
      //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
      //= type=implication
      //# If the input [encryption materials](../structures.md#encryption-
      //# materials) do contain a plaintext data key, OnEncrypt MUST attempt to
      //# encrypt the plaintext data key using the configured AWS KMS key
      //# identifier.
      //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
      //= type=implication
      //# If the input [encryption materials](../structures.md#encryption-
      //# materials) do contain a plaintext data key, OnEncrypt MUST attempt to
      //# encrypt the plaintext data key using the configured AWS KMS key
      //# identifier.
      (plaintext, suite, encryptionContext) -> encrypt(client, keyId, grantTokens, plaintext, encryptionContext),
      //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
      //= type=implication
      //# If the input [encryption materials](../structures.md#encryption-materials)
      //# do not contain a plaintext data key OnEncrypt MUST attempt
      //# to generate a new plaintext data key by calling [AWS KMS
      //# GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/
      //# API_GenerateDataKey.html).
      //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
      //= type=implication
      //# If the input [encryption materials](../structures.md#encryption-
      //# materials) do not contain a plaintext data key OnEncrypt MUST attempt
      //# to generate a new plaintext data key by calling [AWS KMS
      //# GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/
      //# API_GenerateDataKey.html).
      (suite, encryptionContext) -> generate(client, keyId, grantTokens, suite, encryptionContext)
    );
    if (!Utf8.isEncodable(result.info)) {
      throw new ServiceException(KeyringNames.UTF8_FAILURE);
    }
    //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
    //# - the [key provider information](../structures.md#key-provider-
    //# information) MUST be the response `KeyId`.
    byte[] providerInfo = Utf8.encode(result.info);
    if (providerInfo.length >= UINT16_LIMIT) {
      throw new ServiceException("Invalid response from AWS KMS GenerateDataKey: Key ID too long.");
    }
    try {
      //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
      //= type=implication
      //# If
      //# verified, OnEncrypt MUST append a new [encrypted data key]
      //# (../structures.md#encrypted-data-key) to the encrypted data key list
      //# in the [encryption materials](../structures.md#encryption-materials),
      //# constructed as follows:
      //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
      //# - MUST append a new [encrypted data key](../structures.md#encrypted-
      //# data-key) to the encrypted data key list in the [encryption
      //# materials](../structures.md#encryption-materials), constructed as
      //# follows:
      //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
      //# - the [key provider id](../structures.md#key-provider-id) MUST be
      //# "aws-kms".
      //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
      //= type=implication
      //# - MUST output the modified [encryption materials]
      //# (../structures.md#encryption-materials)
      //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
      //= type=implication
      //# If all Encrypt calls succeed, OnEncrypt MUST output the modified
      //# [encryption materials](../structures.md#encryption-materials).
      //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
      //= type=implication
      //# If verified, OnEncrypt MUST do the following with the response
      //# from [AWS KMS GenerateDataKey]
      //# (https://docs.aws.amazon.com/kms/latest/APIReference/
      //# API_GenerateDataKey.html):
      //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
      //= type=implication
      //# If verified, OnEncrypt MUST do the following with the
      //# response from [AWS KMS Encrypt]
      //# (https://docs.aws.amazon.com/kms/latest/APIReference/
      //# API_Encrypt.html):
      //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
      //= type=implication
      //# -  OnEncrypt MUST output the modified [encryption materials]
      //# (../structures.md#encryption-materials)
      //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
      //= type=implication
      //# If all Encrypt calls succeed, OnEncrypt MUST output the modified
      //# [encryption materials](../structures.md#encryption-materials).
      return result.addTo(materials, EncryptedDataKey.of(PROVIDER_ID, providerInfo, result.wrappedMaterial));
    } finally {
      Bytes.zero(result.plaintextDataKey);
      Bytes.zero(result.symmetricSigningKey);
    }
  }

  /** DecryptSingleEncryptedDataKey: KMS Decrypt with {@code keyId}, then the recovered data key added to the materials. */
  public static DecryptionMaterials decrypt(
    KmsClient client,
    String keyId,
    List<String> grantTokens,
    DecryptionMaterials materials,
    EncryptedDataKey edk
  ) {
    EdkWrapping.UnwrapResult<Void> unwrapped = EdkWrapping.unwrap(
      edk.ciphertext(),
      materials,
      (ciphertext, suite, encryptionContext) -> unwrap(client, keyId, grantTokens, ciphertext, suite, encryptionContext)
    );
    //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#ondecrypt
    //= type=implication
    //# If the response does satisfy these requirements then OnDecrypt MUST do the following with the response:
    try {
      //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
      //# - MUST set the plaintext data key on the [decryption materials]
      //# (../structures.md#decryption-materials) as the response
      //# `Plaintext`.
      return unwrapped.addTo(materials);
    } finally {
      Bytes.zero(unwrapped.plaintextDataKey);
      Bytes.zero(unwrapped.symmetricSigningKey);
    }
  }

  /** AwsKmsEncryptedDataKeyDecryptor of the discovery keyrings: the key ARN is checked as a configured key id would be. */
  public static DecryptionMaterials decryptAs(KmsClient client, Candidate candidate, List<String> grantTokens, DecryptionMaterials materials) {
    AwsKmsIdentifier.validateKeyId(candidate.keyId);
    return decrypt(client, candidate.keyId, grantTokens, materials, candidate.edk);
  }

  /** DecryptionMaterialsWithoutPlaintextDataKey, checked first by every keyring's OnDecrypt. */
  public static void requireNoPlaintextDataKey(DecryptionMaterials materials) {
    MaterialsRules.Decryption fields = MaterialsAccess.fields(materials);
    if (fields.plaintextDataKey != null || !MaterialsRules.isValid(fields)) {
      throw new InvalidMaterialsException("Keyring received decryption materials that already contain a plaintext data key.");
    }
  }

  /** OkForDecrypt: decryption names the key by its key ARN. */
  public static void requireKeyArn(AwsKmsIdentifier identifier, String kmsKeyId) {
    if (!identifier.isArn()) {
      throw new ValidationException("KeyID cannot be used for Decrypt : " + kmsKeyId);
    }
    if (!identifier.resourceType().equals("key")) {
      throw new ValidationException("Alias cannot be used for Decrypt : " + kmsKeyId);
    }
  }

  /** Discovery keyrings decrypt only with key ARNs, not alias ARNs. */
  public static void requireKeyResource(AwsKmsIdentifier arn) {
    if (!arn.resourceType().equals("key")) {
      throw new ValidationException("Only AWS KMS Keys supported");
    }
  }

  /** The provider info of an {@code aws-kms} encrypted data key as an ARN; an invalid one fails the whole decryption. */
  public static AwsKmsIdentifier providerInfoArn(EncryptedDataKey edk) {
    String keyId;
    try {
      keyId = KeyringNames.decodeUtf8(edk.keyProviderInfo());
    } catch (ValidationException e) {
      throw new ValidationException("Invalid AWS KMS encoding, provider info is not UTF8.");
    }
    return AwsKmsIdentifier.parseArn(keyId);
  }

  /**
   * Tries each candidate in order and returns the first success.
   * With no candidates, fails with the IncorrectDataKeys message; if all fail, with every failure in order.
   */
  public static <T> DecryptionMaterials firstSuccess(
    List<T> candidates,
    Attempt<T> attempt,
    List<EncryptedDataKey> encryptedDataKeys,
    AlgorithmSuite suite
  ) {
    if (candidates.isEmpty()) {
      throw new NoMatchingDataKeyException(KeyringNames.incorrectDataKeys(encryptedDataKeys, suite), Collections.emptyList());
    }
    List<Throwable> failures = new ArrayList<>();
    //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
    //# For each encrypted data key in the filtered set, one at a time, the
    //# OnDecrypt MUST attempt to decrypt the data key.
    //# If this attempt
    //# results in an error, then these errors MUST be collected.
    //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#ondecrypt
    //# For each encrypted data key in the filtered set, one at a time, the
    //# OnDecrypt MUST attempt to decrypt the data key.
    //# If this attempt
    //# results in an error, then these errors MUST be collected.
    for (T candidate : candidates) {
      try {
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //= type=implication
        //# - MUST immediately return the modified [decryption materials]
        //# (../structures.md#decryption-materials).
        return attempt.decrypt(candidate);
      } catch (RuntimeException e) {
        //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
        //# If the response does not satisfies these requirements then an error
        //# MUST be collected and the next encrypted data key in the filtered set
        //# MUST be attempted.
        //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#ondecrypt
        //# If the response does not satisfies these requirements then an error
        //# MUST be collected and the next encrypted data key in the filtered set
        //# MUST be attempted.
        failures.add(e);
      }
    }
    //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
    //# If OnDecrypt fails to successfully decrypt any [encrypted data key]
    //# (../structures.md#encrypted-data-key), then it MUST yield an error
    //# that includes all the collected errors.
    throw new NoMatchingDataKeyException(ALL_FAILED, failures);
  }

  // KmsGenerateAndWrapKeyMaterial; the info is the KeyId of the response.
  private static EdkWrapping.Generated<String> generate(
    KmsClient client,
    String keyId,
    List<String> grantTokens,
    AlgorithmSuite suite,
    EncryptionContext encryptionContext
  ) {
    //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
    //= type=implication
    //# The keyring MUST call
    //# AWS KMS GenerateDataKeys with a request constructed as follows:
    //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
    //= type=implication
    //# The keyring MUST call
    //# AWS KMS GenerateDataKeys with a request constructed as follows:
    GenerateDataKeyRequest request = GenerateDataKeyRequest
      .builder()
      //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
      //= type=implication
      //# - `KeyId` MUST be the keyring's KMS key identifier.
      .keyId(keyId)
      //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
      //= type=implication
      //# - `EncryptionContext` MUST be the [encryption context]
      //# (../structures.md#encryption-context) included in the input
      //# [encryption materials](../structures.md#encryption-materials).
      .encryptionContext(encryptionContext)
      //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
      //= type=implication
      //# - `GrantTokens` MUST be this keyring's [grant tokens]
      //# (https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
      .grantTokens(grantTokens)
      //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
      //= type=implication
      //# - `NumberOfBytes` MUST be the [key derivation input length]
      //# (../algorithm-suites.md#key-derivation-input-length) specified by
      //# the [algorithm suite](../algorithm-suites.md) included in the input
      //# [encryption materials](../structures.md#encryption-materials).
      .numberOfBytes(suite.dataKeyLength())
      .build();
    GenerateDataKeyResponse response;
    try {
      //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
      //= type=implication
      //# If the keyring calls AWS KMS GenerateDataKeys, it MUST use the
      //# configured AWS KMS client to make the call.
      //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
      //= type=implication
      //# If the keyring calls AWS KMS GenerateDataKeys, it MUST use the
      //# configured AWS KMS client to make the call.
      response = client.generateDataKey(request);
    } catch (SdkException e) {
      //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
      //# If the call to [AWS KMS GenerateDataKey]
      //# (https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html)
      //# does not succeed, OnEncrypt MUST NOT modify
      //# the [encryption materials](../structures.md#encryption-materials) and
      //# MUST fail.
      //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
      //= type=implication
      //# If the call to [AWS KMS GenerateDataKey]
      //# (https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html) does not succeed,
      //# OnEncrypt MUST NOT modify the [encryption materials]
      //# (../structures.md#encryption-materials) and MUST fail.
      throw AwsErrors.from(e);
    }
    //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
    //# The Generate Data Key response’s `KeyId` MUST be [a
    //# valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).
    //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
    //# The Generate Data Key response’s `KeyId` MUST be [A valid AWS
    //# KMS key ARN](aws-kms-key-arn.md#identifying-an-aws-kms-
    //# multi-region-key).
    if (!isIdentifier(response.keyId())) {
      throw new ServiceException("Invalid response from KMS GenerateDataKey:: Invalid Key Id");
    }
    //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
    //= type=implication
    //# If the Generate Data Key call succeeds, OnEncrypt MUST verify that
    //# the response `Plaintext` length matches the specification of the
    //# [algorithm suite](../algorithm-suites.md)'s Key Derivation Input
    //# Length field.
    //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
    //# If the Generate Data Key call succeeds, OnEncrypt MUST
    //# verify that the response `Plaintext` length matches the specification
    //# of the [algorithm suite](../algorithm-suites.md)'s Key Derivation Input Length field.
    if (response.plaintext() == null || response.plaintext().asByteArrayUnsafe().length != suite.dataKeyLength()) {
      throw new ServiceException("Invalid response from AWS KMS GenerateDataKey: Invalid data key");
    }
    if (!isValidCiphertext(response.ciphertextBlob())) {
      throw new ServiceException("Invalid response from AWS KMS GeneratedDataKey: Invalid ciphertext");
    }
    if (response.ciphertextForRecipient() != null) {
      throw new ServiceException("Invalid response from AWS KMS GeneratedDataKey: Invalid CiphertextForRecipient");
    }
    //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
    //# - the [ciphertext](../structures.md#ciphertext) MUST be the
    //# response `CiphertextBlob`.
    return new EdkWrapping.Generated<>(response.plaintext().asByteArray(), response.ciphertextBlob().asByteArray(), response.keyId());
  }

  // KmsWrapKeyMaterial; the info is the KeyId of the response.
  private static EdkWrapping.Wrapped<String> encrypt(
    KmsClient client,
    String keyId,
    List<String> grantTokens,
    byte[] plaintext,
    EncryptionContext encryptionContext
  ) {
    //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
    //= type=implication
    //# The keyring
    //# MUST AWS KMS Encrypt call with a request constructed as follows:
    //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
    //= type=implication
    //# The keyring
    //# MUST AWS KMS Encrypt call with a request constructed as follows:
    EncryptRequest request = EncryptRequest
      .builder()
      //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
      //= type=implication
      //# - `KeyId` MUST be the configured AWS KMS key identifier.
      .keyId(keyId)
      //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
      //# - `EncryptionContext` MUST be the [encryption context]
      //# (../structures.md#encryption-context) included in the input
      //# [encryption materials](../structures.md#encryption-materials).
      .encryptionContext(encryptionContext)
      //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
      //# - `GrantTokens` MUST be this keyring's [grant tokens]
      //# (https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
      .grantTokens(grantTokens)
      //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
      //= type=implication
      //# - `PlaintextDataKey` MUST be the plaintext data key in the
      //# [encryption materials](../structures.md#encryption-materials).
      .plaintext(SdkBytes.fromByteArray(plaintext))
      .build();
    EncryptResponse response;
    try {
      //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
      //= type=implication
      //# The keyring MUST call [AWS KMS Encrypt]
      //# (https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) using the configured AWS KMS client.
      //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
      //= type=implication
      //# The keyring MUST call [AWS KMS Encrypt]
      //# (https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) using the configured AWS KMS client.
      response = client.encrypt(request);
    } catch (SdkException e) {
      //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
      //= type=implication
      //# If the call to [AWS KMS Encrypt]
      //# (https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html)
      //# does not succeed, OnEncrypt MUST fail.
      //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
      //= type=implication
      //# If the call to [AWS KMS Encrypt]
      //# (https://docs.aws.amazon.com/kms/latest/APIReference/
      //# API_Encrypt.html) does not succeed, OnEncrypt MUST fail.
      throw AwsErrors.from(e);
    }
    //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
    //# If the Encrypt call succeeds the response’s `KeyId` MUST be
    //# [A valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).
    //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
    //# If the Encrypt call succeeds the response’s `KeyId` MUST be [A valid
    //# AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).
    if (!isIdentifier(response.keyId())) {
      throw new ServiceException("Invalid response from AWS KMS Encrypt:: Invalid Key Id");
    }
    if (response.ciphertextBlob() == null) {
      throw new ServiceException("Invalid response from AWS KMS Encrypt: Invalid Ciphertext Blob");
    }
    return new EdkWrapping.Wrapped<>(response.ciphertextBlob().asByteArray(), response.keyId());
  }

  // KmsUnwrapKeyMaterial: the response must name the requested key and hold a data key of the suite's length.
  private static EdkWrapping.Unwrapped<Void> unwrap(
    KmsClient client,
    String keyId,
    List<String> grantTokens,
    byte[] ciphertext,
    AlgorithmSuite suite,
    EncryptionContext encryptionContext
  ) {
    if (ciphertext.length < 1 || ciphertext.length > MAX_CIPHERTEXT_LENGTH) {
      throw new ValidationException("Ciphertext length invalid");
    }
    //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
    //= type=implication
    //# When calling [AWS KMS Decrypt]
    //# (https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html),
    //# the keyring MUST call with a request constructed
    //# as follows:
    //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#ondecrypt
    //= type=implication
    //# When calling [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html),
    //# the keyring MUST call with a request constructed as follows:
    //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#ondecrypt
    //= type=implication
    //# When calling [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html), the keyring MUST call with a request constructed as follows:
    DecryptRequest request = DecryptRequest
      .builder()
      //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
      //= type=implication
      //# - `KeyId` MUST be the configured AWS KMS key identifier.
      .keyId(keyId)
      //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
      //= type=implication
      //# - `CiphertextBlob` MUST be the [encrypted data key ciphertext]
      //# (../structures.md#ciphertext).
      .ciphertextBlob(SdkBytes.fromByteArray(ciphertext))
      //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
      //= type=implication
      //# - `EncryptionContext` MUST be the [encryption context]
      //# (../structures.md#encryption-context) included in the input
      //# [decryption materials](../structures.md#decryption-materials).
      .encryptionContext(encryptionContext)
      //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
      //= type=implication
      //# - `GrantTokens` MUST be this keyring's [grant tokens]
      //# (https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
      .grantTokens(grantTokens)
      .build();
    DecryptResponse response;
    try {
      //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
      //= type=implication
      //# To attempt to decrypt a particular [encrypted data key]
      //# (../structures.md#encrypted-data-key), OnDecrypt MUST call [AWS KMS
      //# Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html)
      //# with the configured AWS KMS client.
      //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#ondecrypt
      //= type=implication
      //# To attempt to decrypt a particular [encrypted data key]
      //# (../structures.md#encrypted-data-key), OnDecrypt MUST call [AWS KMS
      //# Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html)
      //# with the configured AWS KMS client.
      response = client.decrypt(request);
    } catch (SdkException e) {
      throw AwsErrors.from(e);
    }
    //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#ondecrypt
    //= type=implication
    //# - The `KeyId` field in the response MUST equal the AWS KMS ARN from the provider info

    //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#ondecrypt
    //= type=implication
    //# - The length of the response’s `Plaintext` MUST equal the [key derivation input length](../algorithm-suites.md#key-derivation-input-length)
    //#  specified by the [algorithm suite](../algorithm-suites.md) included in the input [decryption materials](../structures.md#decryption-materials).

    //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#ondecrypt
    //= type=implication
    //# - The length of the response’s `Plaintext` MUST equal the [key
    //# derivation input length](../algorithm-suites.md#key-derivation-
    //# input-length) specified by the [algorithm suite](../algorithm-
    //# suites.md) included in the input [decryption materials]
    //# (../structures.md#decryption-materials).
    boolean valid =
      //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
      //= type=implication
      //# - The `KeyId` field in the response MUST equal the configured AWS
      //# KMS key identifier.
      //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#ondecrypt
      //= type=implication
      //# - The `KeyId` field in the response MUST equal the configured AWS
      //# KMS key identifier.
      keyId.equals(response.keyId()) &&
      response.plaintext() != null &&
      //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
      //= type=implication
      //# - The length of the response’s `Plaintext` MUST equal the
      //# [key derivation input length](../algorithm-suites.md#key-derivation-input-length)
      //# specified by the [algorithm suite](../algorithm-suites.md)
      //# included in the input [decryption materials]
      //# (../structures.md#decryption-materials).
      //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#ondecrypt
      //= type=implication
      //# - The length of the response’s `Plaintext` MUST equal the [key
      //# derivation input length](../algorithm-suites.md#key-derivation-
      //# input-length) specified by the [algorithm suite](../algorithm-
      //# suites.md) included in the input [decryption materials]
      //# (../structures.md#decryption-materials).
      response.plaintext().asByteArrayUnsafe().length == suite.dataKeyLength();
    if (!valid) {
      throw new ServiceException("Invalid response from KMS Decrypt");
    }
    return new EdkWrapping.Unwrapped<>(response.plaintext().asByteArray(), null);
  }

  private static boolean isIdentifier(String keyId) {
    if (keyId == null) {
      return false;
    }
    try {
      AwsKmsIdentifier.parse(keyId);
      return true;
    } catch (ValidationException e) {
      return false;
    }
  }

  private static boolean isValidCiphertext(SdkBytes ciphertext) {
    return ciphertext != null && ciphertext.asByteArrayUnsafe().length >= 1 && ciphertext.asByteArrayUnsafe().length <= MAX_CIPHERTEXT_LENGTH;
  }
}
