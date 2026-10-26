// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.cmm.DefaultCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.examples.esdk.integration.CommitmentPolicy;
import software.amazon.cryptography.materialproviders.examples.esdk.integration.CryptoAlgorithm;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsKeyring;

/**
 * A default materials manager built once and reused, a chosen algorithm suite, and the commitment policies.
 * ESDK examples: SetEncryptionAlgorithmKeyringExample, SetCommitmentPolicyKeyringExample.
 */
public final class CommitmentPolicyAndAlgorithmExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private CommitmentPolicyAndAlgorithmExample() {}

  /** @param kmsClient real AWS: {@code KmsClient.create()} */
  public static void encryptAndDecrypt(String keyArn, KmsClient kmsClient) {
    // AwsCrypto wraps a keyring in a new default manager on every call; building one up front is the same.
    CryptographicMaterialsManager cmm = DefaultCryptographicMaterialsManager.of(
      AwsKmsKeyring.builder().kmsKeyId(keyArn).kmsClient(kmsClient).build()
    );
    Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // A committing suite without a signature, for when everyone who decrypts is also trusted to encrypt.
    EsdkLikeClient unsigned = EsdkLikeClient.builder().withEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY).build();
    byte[] committed = unsigned.encryptData(cmm, EXAMPLE_DATA, encryptionContext);
    Expect.equal(EXAMPLE_DATA, unsigned.decryptData(cmm, committed, encryptionContext).getResult());

    // Migration from ESDK 1.x: write messages old readers understand, read both kinds.
    EsdkLikeClient legacyWriter = EsdkLikeClient.builder().withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt).build();
    byte[] uncommitted = legacyWriter.encryptData(cmm, EXAMPLE_DATA, encryptionContext);
    Expect.equal(EXAMPLE_DATA, legacyWriter.decryptData(cmm, committed, encryptionContext).getResult());

    // The default policy, RequireEncryptRequireDecrypt, refuses to read it ...
    EsdkLikeClient strict = EsdkLikeClient.builder().build();
    Expect.failure(EsdkLikeClient.AwsCryptoException.class, () -> strict.decryptData(cmm, uncommitted, encryptionContext));
    // ... and the materials manager refuses to encrypt with a non-committing suite under it.
    EsdkLikeClient conflicting = EsdkLikeClient
      .builder()
      .withEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384)
      .build();
    Expect.failure(ValidationException.class, () -> conflicting.encryptData(cmm, EXAMPLE_DATA, encryptionContext));
  }
}
