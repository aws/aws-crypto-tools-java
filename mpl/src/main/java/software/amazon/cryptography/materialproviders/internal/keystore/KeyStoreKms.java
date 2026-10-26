// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.keystore;

import java.util.List;
import java.util.Map;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyWithoutPlaintextResponse;
import software.amazon.awssdk.services.kms.model.ReEncryptResponse;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.exceptions.ServiceException;
import software.amazon.cryptography.materialproviders.internal.AwsErrors;
import software.amazon.cryptography.materialproviders.internal.primitives.Bytes;

/** The key store's KMS calls and the checks on their responses, per KMSKeystoreOperations.dfy. */
final class KeyStoreKms {

  private static final int BRANCH_KEY_LENGTH = 32;

  private final KmsConfiguration kmsConfiguration;
  private final List<String> grantTokens;
  private final KmsClient kms;

  KeyStoreKms(KmsConfiguration kmsConfiguration, List<String> grantTokens, KmsClient kms) {
    this.kmsConfiguration = kmsConfiguration;
    this.grantTokens = grantTokens;
    this.kms = kms;
  }

  /**
   * AttemptKmsOperation?: whether the configuration lets the store use the KMS key that {@code context} names.
   * An exact match for a key ARN, a multi-Region match for a multi-Region key ARN, and any valid key ARN for discovery.
   */
  boolean mayUse(Map<String, String> context) {
    String storedArn = context.get(KeyStoreItems.KMS_FIELD);
    switch (kmsConfiguration.kind()) {
      case KMS_KEY_ARN:
        return configuredArn().equals(storedArn);
      case KMS_MR_KEY_ARN:
        return Arns.mrkMatch(configuredArn(), storedArn);
      default:
        // Reads check that the stored ARN is a valid key ARN first, and discovery stores do not version keys.
        return true;
    }
  }

  /** A new wrapped 32-byte key under the configured KMS key, bound to {@code context}. */
  byte[] generateKey(Map<String, String> context) {
    GenerateDataKeyWithoutPlaintextResponse response;
    try {
      //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
      //= type=implication
      //# The operation MUST call [AWS KMS API GenerateDataKeyWithoutPlaintext](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyWithoutPlaintext.html).

      //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
      //= type=implication
      //# The call to AWS KMS GenerateDataKeyWithoutPlaintext MUST use the configured AWS KMS client to make the call.

      //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
      //= type=implication
      //# The operation MUST call AWS KMS GenerateDataKeyWithoutPlaintext with a request constructed as follows:

      //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
      //= type=implication
      //# - `KeyId` MUST be [compatible with](#aws-key-arn-compatibility) the configured KMS Key in the [AWS KMS Configuration](#aws-kms-configuration) for this keystore.

      //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
      //= type=implication
      //# - `NumberOfBytes` MUST be 32.

      //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
      //= type=implication
      //# - `GrantTokens` MUST be this keystore's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).

      //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
      //= type=implication
      //# The operation MUST call [AWS KMS API GenerateDataKeyWithoutPlaintext](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyWithoutPlaintext.html).

      //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
      //= type=implication
      //# The call to AWS KMS GenerateDataKeyWithoutPlaintext MUST use the configured AWS KMS client to make the call.

      //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
      //= type=implication
      //# The operation MUST call AWS KMS GenerateDataKeyWithoutPlaintext with a request constructed as follows:

      //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
      //= type=implication
      //# - `KeyId` MUST be [compatible with](#aws-key-arn-compatibility) the configured KMS Key in the [AWS KMS Configuration](#aws-kms-configuration) for this keystore.

      //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
      //= type=implication
      //# - `NumberOfBytes` MUST be 32.

      //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
      //= type=implication
      //# - GenerateDataKeyWithoutPlaintext `GrantTokens` MUST be this keystore's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
      response = kms.generateDataKeyWithoutPlaintext(r ->
        r.keyId(configuredArn()).encryptionContext(context).numberOfBytes(BRANCH_KEY_LENGTH).grantTokens(grantTokens)
      );
    } catch (SdkException e) {
      throw AwsErrors.from(e);
    }
    if (response.keyId() == null) {
      throw new ServiceException(KeyStoreMessages.GENERATE_INVALID_KEY_ID);
    }
    if (response.ciphertextBlob() == null || !KeyStoreItems.isValidCiphertext(response.ciphertextBlob().asByteArray())) {
      throw new ServiceException(KeyStoreMessages.GENERATE_INVALID_CIPHERTEXT);
    }
    return response.ciphertextBlob().asByteArray();
  }

  /**
   * {@code ciphertext} rewrapped from {@code source} to {@code destination} under the configured KMS key.
   * KMS authenticates {@code source} while doing so.
   */
  byte[] reEncrypt(byte[] ciphertext, Map<String, String> source, Map<String, String> destination) {
    String arn = configuredArn();
    ReEncryptResponse response;
    try {
      //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
      //= type=implication
      //# The operation MUST call [AWS KMS API ReEncrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html)
      //# with a request constructed as follows:

      //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
      //= type=implication
      //# - `SourceKeyId` MUST be [compatible with](#aws-key-arn-compatibility) the configured KMS Key in the [AWS KMS Configuration](#aws-kms-configuration) for this keystore.

      //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
      //= type=implication
      //# - `DestinationKeyId` MUST be [compatible with](#aws-key-arn-compatibility) the configured KMS Key in the [AWS KMS Configuration](#aws-kms-configuration) for this keystore.

      //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
      //= type=implication
      //# - ReEncrypt `GrantTokens` MUST be this keystore's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).

      //= spec/framework/branch-key-store.md#authenticating-a-keystore-item
      //= type=implication
      //# The operation MUST use the configured `KMS SDK Client` to authenticate the value of the keystore item.

      //= spec/framework/branch-key-store.md#authenticating-a-keystore-item
      //= type=implication
      //# - `SourceKeyId` MUST be [compatible with](#aws-key-arn-compatibility) the configured KMS Key in the [AWS KMS Configuration](#aws-kms-configuration) for this keystore.

      //= spec/framework/branch-key-store.md#authenticating-a-keystore-item
      //= type=implication
      //# - `GrantTokens` MUST be the configured [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).

      //= spec/framework/branch-key-store.md#authenticating-a-keystore-item
      //= type=implication
      //# - `DestinationKeyId` MUST be [compatible with](#aws-key-arn-compatibility) the configured KMS Key in the [AWS KMS Configuration](#aws-kms-configuration) for this keystore.
      response = kms.reEncrypt(r ->
        r
          .ciphertextBlob(SdkBytes.fromByteArray(ciphertext))
          .sourceEncryptionContext(source)
          .sourceKeyId(arn)
          .destinationKeyId(arn)
          .destinationEncryptionContext(destination)
          .grantTokens(grantTokens)
      );
    } catch (SdkException e) {
      throw AwsErrors.from(e);
    }
    if (!arn.equals(response.sourceKeyId()) || !arn.equals(response.keyId())) {
      throw new ServiceException(KeyStoreMessages.RE_ENCRYPT_INVALID_KEY_ID);
    }
    if (response.ciphertextBlob() == null || !KeyStoreItems.isValidCiphertext(response.ciphertextBlob().asByteArray())) {
      throw new ServiceException(KeyStoreMessages.RE_ENCRYPT_INVALID_CIPHERTEXT);
    }
    return response.ciphertextBlob().asByteArray();
  }

  /** The 32-byte plaintext of a stored key; the caller owns and clears the array. */
  byte[] decrypt(byte[] wrappedKey, Map<String, String> context) {
    String keyId = decryptKeyId(context.get(KeyStoreItems.KMS_FIELD));
    DecryptResponse response;
    try {
      //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
      //= type=implication
      //# The operation MUST use the configured `KMS SDK Client` to decrypt the value of the branch key field.

      //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
      //= type=implication
      //# When calling [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html),
      //# the keystore operation MUST call with a request constructed as follows:

      //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
      //= type=implication
      //# - `CiphertextBlob` MUST be the `enc` attribute value on the AWS DDB response item

      //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
      //= type=implication
      //# Every attribute except for `enc` on the AWS DDB response item
      //# MUST be authenticated in the decryption of `enc`

      //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
      //= type=implication
      //# - `EncryptionContext` MUST be the [encryption context](#encryption-context) constructed above

      //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
      //= type=implication
      //# - `GrantTokens` MUST be this keystore's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
      response = kms.decrypt(r ->
        r.ciphertextBlob(SdkBytes.fromByteArray(wrappedKey)).encryptionContext(context).grantTokens(grantTokens).keyId(keyId)
      );
    } catch (SdkException e) {
      throw AwsErrors.from(e);
    }
    byte[] plaintext = response.plaintext() == null ? null : response.plaintext().asByteArray();
    if (plaintext == null || plaintext.length != BRANCH_KEY_LENGTH) {
      Bytes.zero(plaintext);
      throw new ServiceException(KeyStoreMessages.DECRYPT_INVALID_KEY);
    }
    return plaintext;
  }

  // GetArn: the configured key for the ARN kinds; for discovery the stored key,
  // in the configured region if it is a multi-Region key and the configuration is MR-discovery.
  private String decryptKeyId(String storedArn) {
    switch (kmsConfiguration.kind()) {
      //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
      //= type=implication
      //# Otherwise, it MUST BE the Keystore's configured KMS Key.
      case KMS_KEY_ARN:
      case KMS_MR_KEY_ARN:
        return configuredArn();
      //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
      //= type=implication
      //# If the KMS Configuration is MRDiscovery, `KeyId` MUST be the `kms-arn` attribute value of the AWS DDB response item, with the region replaced by the configured region.
      case MR_DISCOVERY:
        return Arns.replaceRegion(storedArn, kmsConfiguration.region().get());
      //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
      //= type=implication
      //# - `KeyId`, if the KMS Configuration is Discovery, MUST be the `kms-arn` attribute value of the AWS DDB response item.
      default:
        return storedArn;
    }
  }

  private String configuredArn() {
    return kmsConfiguration.arn().get();
  }
}
